from __future__ import annotations

import json
from pathlib import Path

import requests

import iocparser.infrastructure.warninglists_service as warninglists_service_module
from iocparser.domain.models import IOC
from iocparser.infrastructure.warninglists import MISPWarningLists, WarningListLookups


class InitProbeWarningLists(MISPWarningLists):
    def __init__(self, data_dir: Path) -> None:
        self.load_called = False
        self.preprocess_called = False
        self._probe_data_dir = data_dir
        super().__init__(cache_duration=12, force_update=True)

    def _load_or_update_lists(self) -> None:
        self.load_called = True
        self.warning_lists = {
            "probe": {
                "name": "Probe",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["probe.example"],
            }
        }

    def _preprocess_lists(self) -> None:
        self.preprocess_called = True
        super()._preprocess_lists()


class CacheFallbackWarningLists(MISPWarningLists):
    def __init__(self, data_dir: Path) -> None:
        self.cache_duration = 24
        self.force_update = False
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

    def _fetch_list_directories(self) -> list[str]:
        raise requests.RequestException("boom")


class ServiceBackedWarningLists:
    def __init__(self, *, force_update: bool = False) -> None:
        self.force_update = force_update

    def separate_iocs_by_warnings(
        self,
        grouped_iocs: dict[str, list[str | dict[str, str]]],
    ) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
        assert self.force_update is True
        return (
            {"domains": ["safe.example"]},
            {
                "domains": [
                    {
                        "value": str(grouped_iocs["domains"][0]),
                        "warning_list": "Known Good",
                        "description": "covered in service test",
                    }
                ]
            },
        )


def test_warninglists_real_init_sets_paths_and_preprocesses(tmp_path: Path) -> None:
    original_file = MISPWarningLists.__init__.__globals__["__file__"]
    MISPWarningLists.__init__.__globals__["__file__"] = str(tmp_path / "warninglists.py")
    try:
        warning_lists = InitProbeWarningLists(tmp_path)
    finally:
        MISPWarningLists.__init__.__globals__["__file__"] = original_file

    assert warning_lists.cache_duration == 12
    assert warning_lists.force_update is True
    assert warning_lists.load_called is True
    assert warning_lists.preprocess_called is True
    assert warning_lists.data_dir == tmp_path / "data"
    assert warning_lists.cache_file == warning_lists.data_dir / "misp_warninglists_cache.json"
    assert (
        warning_lists.cache_metadata_file
        == warning_lists.data_dir / "misp_warninglists_metadata.json"
    )
    assert warning_lists.data_dir.exists()


def test_warninglists_update_uses_cached_lists_after_request_failure(tmp_path: Path) -> None:
    cache_file = tmp_path / "misp_warninglists_cache.json"
    cache_file.write_text(
        json.dumps(
            {
                "cached": {
                    "name": "Cached",
                    "type": "string",
                    "matching_attributes": ["domain"],
                    "list": ["cached.example"],
                }
            }
        ),
        encoding="utf-8",
    )

    warning_lists = object.__new__(CacheFallbackWarningLists)
    warning_lists.cache_duration = 24
    warning_lists.force_update = False
    warning_lists.warning_lists = {}
    warning_lists.data_dir = tmp_path
    warning_lists.cache_file = cache_file
    warning_lists.cache_metadata_file = tmp_path / "misp_warninglists_metadata.json"
    warning_lists.lookup_data = WarningListLookups(
        string_lookups={},
        compiled_regex={},
        cidr_networks={},
        lists_by_ioc_type={},
    )

    CacheFallbackWarningLists._update_warning_lists(warning_lists)

    assert warning_lists.warning_lists["cached"]["name"] == "Cached"


def test_warninglist_service_separates_iocs_through_adapter() -> None:
    original = warninglists_service_module.MISPWarningLists
    warninglists_service_module.MISPWarningLists = ServiceBackedWarningLists
    try:
        result = warninglists_service_module.MISPWarningListService().separate(
            (IOC.from_raw("domains", "safe.example"),),
            force_update=True,
        )
    finally:
        warninglists_service_module.MISPWarningLists = original

    assert result.grouped_iocs() == {"domains": ["safe.example"]}
    assert result.grouped_warnings() == {
        "domains": [
            {
                "value": "safe.example",
                "warning_list": "Known Good",
                "description": "covered in service test",
            }
        ]
    }
