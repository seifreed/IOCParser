from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from iocparser.infrastructure.warninglists import MISPWarningLists, WarningListLookups
from tests.http_server_helpers import ThreadedHTTPServer

GOOD_BAD_DOMAIN_PAYLOADS: dict[str, tuple[int, object]] = {
    "good-domains": (
        200,
        {
            "name": "Good Domains",
            "type": "string",
            "matching_attributes": ["domain"],
            "list": ["good.example"],
        },
    ),
    "bad-domains": (500, {}),
}


class OfflineWarningLists(MISPWarningLists):
    def __init__(
        self, data_dir: Path, *, cache_duration: int = 24, force_update: bool = False
    ) -> None:
        self.cache_duration = cache_duration
        self.force_update = force_update
        self.warning_lists = {}
        self.data_dir = data_dir
        self.cache_file = data_dir / "misp_warninglists_cache.json"
        self.cache_metadata_file = data_dir / "misp_warninglists_metadata.json"
        self.lookup_data = WarningListLookups(
            string_lookups={},
            compiled_regex={},
            cidr_networks={},
            lists_by_ioc_type={},
        )
        self.data_dir.mkdir(parents=True, exist_ok=True)


class TrackingWarningLists(OfflineWarningLists):
    def __init__(
        self, data_dir: Path, *, cache_duration: int = 24, force_update: bool = False
    ) -> None:
        super().__init__(data_dir, cache_duration=cache_duration, force_update=force_update)
        self.updated = False

    def _update_warning_lists(self) -> None:
        self.updated = True
        self.warning_lists = {
            "fallback": {
                "name": "Fallback",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["fallback.example"],
            }
        }


@contextmanager
def patched_github_bases(base_url: str) -> Iterator[None]:
    """Point OfflineWarningLists at a local server for the duration of the block."""
    original_api = OfflineWarningLists.GITHUB_API_BASE
    original_raw = OfflineWarningLists.GITHUB_RAW_BASE
    OfflineWarningLists.GITHUB_API_BASE = f"{base_url}/contents/lists"
    OfflineWarningLists.GITHUB_RAW_BASE = f"{base_url}/lists"
    try:
        yield
    finally:
        OfflineWarningLists.GITHUB_API_BASE = original_api
        OfflineWarningLists.GITHUB_RAW_BASE = original_raw


class WarningListServer(ThreadedHTTPServer):
    path = ""

    def __init__(self, directories: list[str], payloads: dict[str, tuple[int, object]]) -> None:
        self.directories = directories
        self.payloads = payloads

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        directories = self.directories
        payloads = self.payloads

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/contents/lists":
                    body = json.dumps(
                        [{"name": name, "type": "dir"} for name in directories]
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path.startswith("/lists/") and self.path.endswith("/list.json"):
                    directory = self.path.split("/")[2]
                    status, payload = payloads[directory]
                    body = json.dumps(payload).encode("utf-8") if status == 200 else b"error"
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args) -> None:
                del format, args

        return Handler


def test_load_or_update_lists_uses_valid_cache_without_network(tmp_path: Path) -> None:
    warning_lists = TrackingWarningLists(tmp_path)
    warning_lists.cache_metadata_file.write_text(
        json.dumps({"last_update": time.time()}), encoding="utf-8"
    )
    warning_lists.cache_file.write_text(
        json.dumps(
            {
                "cached-domains": {
                    "name": "Cached Domains",
                    "type": "string",
                    "matching_attributes": ["domain"],
                    "list": ["cached.example"],
                }
            }
        ),
        encoding="utf-8",
    )

    warning_lists._load_or_update_lists()

    assert warning_lists.updated is False
    assert "cached-domains" in warning_lists.warning_lists


def test_load_or_update_lists_resets_corrupted_cache_and_triggers_update(tmp_path: Path) -> None:
    warning_lists = TrackingWarningLists(tmp_path)
    warning_lists.cache_metadata_file.write_text("{broken", encoding="utf-8")
    warning_lists.cache_file.write_text("{}", encoding="utf-8")

    warning_lists._load_or_update_lists()

    assert warning_lists.updated is True
    assert not warning_lists.cache_metadata_file.exists()
    assert not warning_lists.cache_file.exists()


def test_load_or_update_lists_handles_cache_open_errors(tmp_path: Path) -> None:
    warning_lists = TrackingWarningLists(tmp_path)
    warning_lists.cache_metadata_file.mkdir()
    warning_lists.cache_file.write_text("{}", encoding="utf-8")

    warning_lists._load_or_update_lists()

    assert warning_lists.updated is True


def test_safe_unlink_ignores_unlink_errors(tmp_path: Path) -> None:
    warning_lists = OfflineWarningLists(tmp_path)
    directory = tmp_path / "cache-dir"
    directory.mkdir()

    warning_lists._safe_unlink(directory)

    assert directory.exists()


def test_update_warning_lists_downloads_from_local_server_and_writes_cache(tmp_path: Path) -> None:
    warning_lists = OfflineWarningLists(tmp_path)
    payloads = GOOD_BAD_DOMAIN_PAYLOADS

    with (
        WarningListServer(["good-domains", "bad-domains"], payloads) as base_url,
        patched_github_bases(base_url),
    ):
        warning_lists._update_warning_lists()

    assert "good-domains" in warning_lists.warning_lists
    assert warning_lists.cache_file.exists()
    assert warning_lists.cache_metadata_file.exists()


def test_update_warning_lists_falls_back_to_cache_and_handles_bad_cache(tmp_path: Path) -> None:
    warning_lists = OfflineWarningLists(tmp_path)
    warning_lists.cache_file.write_text("{broken", encoding="utf-8")

    class BadJSONServer(ThreadedHTTPServer):
        path = ""

        def build_handler(self) -> type[BaseHTTPRequestHandler]:
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    body = b"not-json"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format: str, *args) -> None:
                    del format, args

            return Handler

    with BadJSONServer() as base_url, patched_github_bases(base_url):
        warning_lists._update_warning_lists()

    assert warning_lists.warning_lists == {}


def test_preprocess_and_matching_helpers_cover_edge_cases(tmp_path: Path) -> None:
    warning_lists = OfflineWarningLists(tmp_path)
    warning_lists.warning_lists = {
        "string-list": {
            "name": "String List",
            "type": "string",
            "matching_attributes": [{"name": "domain"}, 42],
            "list": ["alpha.example", None],
        },
        "regex-list": {
            "name": "Regex List",
            "type": "regex",
            "matching_attributes": "not-a-list",
            "list": [r".*beta\.example$", None],
        },
        "cidr-list": {
            "name": "CIDR List",
            "type": "cidr",
            "matching_attributes": ["ip-src"],
            "list": ["203.0.113.0/24", "not-a-cidr", None, "203.0.113.5"],
        },
    }

    warning_lists._preprocess_lists()
    warning_lists._log_failed_downloads([])
    warning_lists._log_failed_downloads(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"])

    assert warning_lists.string_lookups["alpha.example"] == {"string-list"}
    assert "regex-list" not in warning_lists.lists_by_ioc_type
    assert "cidr-list" in warning_lists.lists_by_ioc_type["ips"]
    assert warning_lists._extract_email_domain("invalid-email") is None
    result, info = warning_lists._email_domain_in_warning_list("invalid-email")
    assert result is False
    assert info is None


def test_warninglist_lookup_helpers_cover_url_substring_and_invalid_inputs(tmp_path: Path) -> None:
    warning_lists = OfflineWarningLists(tmp_path)
    warning_lists.warning_lists = {
        "domains": {
            "name": "Safe Domains",
            "type": "string",
            "matching_attributes": ["domain", "url"],
            "list": ["lookup.example"],
        },
        "substring-list": {
            "name": "Substring Domains",
            "type": "substring",
            "matching_attributes": ["url"],
            "list": ["portal"],
        },
    }
    warning_lists._preprocess_lists()

    is_warning, info = warning_lists.check_value("https://lookup.example/path", "urls")
    assert is_warning is True
    assert info is not None
    assert info["name"] == "Safe Domains"

    substring_warning = warning_lists._check_substring_lists(
        "https://portal.example/path",
        "portal.example",
        ["missing", "substring-list"],
        "urls",
    )
    assert substring_warning is not None
    assert substring_warning["name"] == "Substring Domains"

    warning_lists.warning_lists["non-applicable-substring"] = {
        "name": "Email Substring",
        "type": "substring",
        "matching_attributes": ["email"],
        "list": ["portal"],
    }
    assert (
        warning_lists._check_substring_lists(
            "https://portal.example/path",
            "portal.example",
            ["non-applicable-substring"],
            "urls",
        )
        is None
    )

    assert warning_lists._extract_domain_from_url("http://[::1") is None
    assert warning_lists._check_cidr("203.0.113.10", [None, "203.0.113.0/24"]) is True
