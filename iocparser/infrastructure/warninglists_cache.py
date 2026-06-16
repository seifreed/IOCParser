from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging import Logger
from pathlib import Path
from typing import ClassVar, cast

import requests
from tqdm import tqdm

from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.warninglists_types import JSONData, WarningListDict, get_mixin_logger

logger = get_logger("iocparser.infrastructure.warninglists")


class WarningListCacheMixin:
    """Cache loading and remote update support for warning lists."""

    logger: Logger
    cache_file: Path
    cache_metadata_file: Path
    cache_duration: int
    force_update: bool
    warning_lists: dict[str, WarningListDict]
    GITHUB_API_BASE: ClassVar[str]
    GITHUB_RAW_BASE: ClassVar[str]

    def _get_logger(self) -> Logger:
        return get_mixin_logger(self, logger)

    def _reset_cache_files(self) -> None:
        for cache_path in (self.cache_file, self.cache_metadata_file):
            self._safe_unlink(cache_path)

    def _safe_unlink(self, cache_path: Path) -> None:
        current_logger = self._get_logger()
        try:
            cache_path.unlink(missing_ok=True)
        except (OSError, PermissionError) as cleanup_error:
            current_logger.debug("Could not remove cache file %s: %s", cache_path, cleanup_error)

    def _load_or_update_lists(self) -> None:
        current_logger = self._get_logger()
        if (
            not self.force_update
            and self.cache_duration > 0
            and self.cache_file.exists()
            and self.cache_metadata_file.exists()
        ):
            try:
                with self.cache_metadata_file.open() as handle:
                    metadata: dict[str, float] = json.load(handle)
                last_update_raw = metadata.get("last_update", 0.0)
                try:
                    last_update = float(last_update_raw)
                except (TypeError, ValueError):
                    last_update = 0.0
                current_time = time.time()
                if current_time - last_update < self.cache_duration * 3600:
                    current_logger.info("Loading MISP warning lists from local cache...")
                    with self.cache_file.open() as handle:
                        loaded_data: JSONData = json.load(handle)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    current_logger.info(
                        "Loaded %s MISP warning lists from cache",
                        len(self.warning_lists),
                    )
                    return
            except json.JSONDecodeError as exc:
                current_logger.warning(
                    "Cache is corrupted (JSON decode error): %s. Resetting cache.",
                    exc,
                )
                self._reset_cache_files()
            except (OSError, ValueError) as exc:
                current_logger.warning("Failed to load cache: %s", exc)
                self._reset_cache_files()
        self._update_warning_lists()

    def _fetch_list_directories(self) -> list[str]:
        response = requests.get(self.GITHUB_API_BASE, timeout=30)
        response.raise_for_status()
        response_data: JSONData = response.json()
        directories = cast("list[dict[str, str]]", response_data)
        return [item["name"] for item in directories if item.get("type") == "dir"]

    def _download_single_list(self, directory: str) -> tuple[str, WarningListDict | None]:
        current_logger = self._get_logger()
        try:
            list_url = f"{self.GITHUB_RAW_BASE}/{directory}/list.json"
            list_response = requests.get(list_url, timeout=30)
            list_response.raise_for_status()
            response_json: JSONData = list_response.json()
            result: WarningListDict = cast("WarningListDict", response_json)
            return directory, result
        except (requests.RequestException, ValueError) as exc:
            current_logger.warning("Error downloading warning list %s: %s", directory, exc)
            return directory, None

    def _download_warning_lists(
        self,
        list_directories: list[str],
    ) -> tuple[dict[str, WarningListDict], list[str]]:
        warning_lists: dict[str, WarningListDict] = {}
        failed_downloads: list[str] = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self._download_single_list, directory)
                for directory in list_directories
            ]
            for future in tqdm(
                as_completed(futures),
                total=len(list_directories),
                desc="Downloading warning lists",
            ):
                directory, warning_list = future.result()
                if warning_list is not None:
                    warning_lists[directory] = warning_list
                else:
                    failed_downloads.append(directory)
        return warning_lists, failed_downloads

    def _write_cache(self, *, complete: bool = True) -> None:
        with self.cache_file.open("w") as handle:
            json.dump(self.warning_lists, handle)
        # On a partial download keep what we got as an offline fallback, but stamp the
        # metadata stale so the next run retries the full fetch instead of trusting an
        # incomplete set for the whole cache window (silent enrichment false-negatives).
        last_update = time.time() if complete else 0.0
        cache_data: dict[str, float] = {"last_update": last_update}
        with self.cache_metadata_file.open("w") as handle:
            json.dump(cache_data, handle)

    def _log_failed_downloads(self, failed_downloads: list[str]) -> None:
        if not failed_downloads:
            return
        current_logger = self._get_logger()
        failed_head = ", ".join(failed_downloads[:10])
        suffix = " ..." if len(failed_downloads) > 10 else ""
        current_logger.warning(
            "Failed to download %s warning lists: %s%s",
            len(failed_downloads),
            failed_head,
            suffix,
        )

    def _update_warning_lists(self) -> None:
        current_logger = self._get_logger()
        try:
            current_logger.warning("Updating MISP warning lists from GitHub repository...")
            list_directories = self._fetch_list_directories()
            current_logger.info("Downloading %s MISP warning lists...", len(list_directories))
            warning_lists, failed_downloads = self._download_warning_lists(list_directories)
            self.warning_lists = warning_lists
            self._write_cache(complete=not failed_downloads)
            self._log_failed_downloads(failed_downloads)
            current_logger.info(
                "Successfully updated %s MISP warning lists", len(self.warning_lists)
            )
        except (OSError, ValueError, requests.RequestException, json.JSONDecodeError):
            current_logger.exception("Could not update warning lists")
            if self.cache_file.exists():
                try:
                    with self.cache_file.open() as handle:
                        loaded_data: JSONData = json.load(handle)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    current_logger.warning("Using cached warning lists")
                except (OSError, ValueError, json.JSONDecodeError):
                    current_logger.exception("Could not load warning lists from cache")
            if not self.warning_lists:
                current_logger.warning(
                    "WARNING LISTS UNAVAILABLE: No warning lists could be loaded. "
                    "All IOCs will pass without warning-list enrichment."
                )
