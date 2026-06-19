from __future__ import annotations

import json
from pathlib import Path

import requests
import pytest

import iocparser.infrastructure.warninglists_service as warninglists_service_module
from iocparser.domain.models import IOC
from iocparser.infrastructure.warninglists import MISPWarningLists
from tests.test_warninglists_offline import OfflineWarningLists


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


class CacheFallbackWarningLists(OfflineWarningLists):
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


class ServiceBackedBadWarningLists:
    def __init__(self, *, force_update: bool = False) -> None:
        self.force_update = force_update

    def separate_iocs_by_warnings(
        self,
        grouped_iocs: dict[str, list[str | dict[str, str]]],
    ) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
        assert self.force_update is True
        del grouped_iocs
        return ({}, {"domains": [{"value": object(), "warning_list": "Known Good", "description": ""}]})


class ServiceBackedBadNormalWarningLists:
    def __init__(self, *, force_update: bool = False) -> None:
        self.force_update = force_update

    def separate_iocs_by_warnings(
        self,
        grouped_iocs: dict[str, list[str | dict[str, str]]],
    ) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
        assert self.force_update is True
        del grouped_iocs
        return ({"domains": [object()]}, {})


class ServiceBackedDictNormalWarningLists:
    def __init__(self, *, force_update: bool = False) -> None:
        self.force_update = force_update

    def separate_iocs_by_warnings(
        self,
        grouped_iocs: dict[str, list[str | dict[str, str]]],
    ) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
        assert self.force_update is True
        del grouped_iocs
        return ({"domains": [{"value": "safe.example", "file": "note.txt"}]}, {})


class _BadRawValue:
    def __init__(self) -> None:
        self.raw = object()


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
    assert warning_lists.cache_dir.exists()
    assert warning_lists.cache_file.parent == warning_lists.cache_dir
    assert warning_lists.cache_metadata_file.parent == warning_lists.cache_dir
    assert warning_lists.cache_file.parent != warning_lists.data_dir
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

    warning_lists = CacheFallbackWarningLists(tmp_path)
    assert warning_lists.cache_file == cache_file

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


def test_warninglist_service_rejects_non_string_raw_values() -> None:
    with pytest.raises(TypeError, match="Expected raw to be string-like"):
        warninglists_service_module.MISPWarningListService().separate(
            (IOC(ioc_type="domains", value=_BadRawValue()),),
            force_update=True,
        )


def test_warninglist_service_rejects_non_string_warning_output() -> None:
    original = warninglists_service_module.MISPWarningLists
    warninglists_service_module.MISPWarningLists = ServiceBackedBadWarningLists
    try:
        with pytest.raises(TypeError, match="Expected value to be string-like"):
            warninglists_service_module.MISPWarningListService().separate(
                (IOC.from_raw("domains", "safe.example"),),
                force_update=True,
            )
    finally:
        warninglists_service_module.MISPWarningLists = original


def test_warninglist_service_rejects_non_string_normal_output() -> None:
    original = warninglists_service_module.MISPWarningLists
    warninglists_service_module.MISPWarningLists = ServiceBackedBadNormalWarningLists
    try:
        with pytest.raises(TypeError, match="Expected value to be string-like"):
            warninglists_service_module.MISPWarningListService().separate(
                (IOC.from_raw("domains", "safe.example"),),
                force_update=True,
            )
    finally:
        warninglists_service_module.MISPWarningLists = original


def test_warninglist_service_accepts_dict_normal_output() -> None:
    original = warninglists_service_module.MISPWarningLists
    warninglists_service_module.MISPWarningLists = ServiceBackedDictNormalWarningLists
    try:
        result = warninglists_service_module.MISPWarningListService().separate(
            (IOC.from_raw("domains", "safe.example"),),
            force_update=True,
        )
    finally:
        warninglists_service_module.MISPWarningLists = original

    assert result.grouped_iocs() == {"domains": ["safe.example"]}
