from __future__ import annotations

import json
import re as _re
import sys
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import cast

from iocparser.infrastructure.logger import get_logger

logger = get_logger(__name__)

COMMON_FILE_EXTENSIONS: set[str] = {
    "exe",
    "dll",
    "sys",
    "cmd",
    "bat",
    "ps1",
    "vbs",
    "js",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "zip",
    "rar",
    "7z",
    "gz",
    "tar",
    "pif",
    "scr",
    "msi",
    "jar",
    "py",
    "pyc",
    "pyo",
    "php",
    "asp",
    "aspx",
    "jsp",
    "htm",
    "html",
    "css",
    "json",
    "xml",
    "reg",
    "ini",
    "cfg",
    "log",
    "tmp",
    "dat",
    "db",
    "sqlite",
    "iso",
    "img",
    "vhd",
    "vmdk",
}

COMMON_TLDS: set[str] = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "museum",
    "aero",
    "coop",
    "jobs",
    "travel",
    "mobi",
    "asia",
    "tel",
    "xxx",
    "post",
    "cat",
    "arpa",
    "top",
    "xyz",
    "club",
    "online",
    "site",
    "shop",
    "app",
    "blog",
    "dev",
    "art",
    "web",
    "cloud",
    "page",
    "store",
    "host",
    "tech",
    "space",
    "live",
    "news",
    "io",
    "co",
    "me",
    "tv",
    "us",
    "uk",
    "ru",
    "fr",
    "de",
    "jp",
    "cn",
    "au",
    "ca",
    "in",
    "it",
    "nl",
    "se",
    "no",
    "fi",
    "dk",
    "ch",
    "at",
    "be",
    "es",
    "pt",
    "br",
    "mx",
    "ar",
    "cl",
    "pe",
    "ve",
    "za",
    "pl",
    "cz",
    "gr",
    "hu",
    "ro",
    "ua",
    "by",
    "kz",
    "th",
    "sg",
    "my",
    "ph",
    "vn",
    "id",
    "tr",
    "il",
    "ae",
    "sa",
    "ir",
    "pk",
    "eg",
    "ng",
    "kr",
    "tw",
    "hk",
    "mo",
    "eu",
    "nz",
    "ai",
    "gg",
    "im",
    "je",
}


@dataclass(frozen=True)
class ReferenceDataPolicy:
    default_tlds: frozenset[str]
    common_file_extensions: frozenset[str]

    def get_data_dir(self, module_name: str) -> Path:
        module: ModuleType | None = sys.modules.get(module_name)
        module_file = module.__file__ if module is not None else None
        if isinstance(module_file, str):
            module_path = Path(module_file).parent
            direct_data_dir = module_path / "data"
            if direct_data_dir.exists():
                return direct_data_dir
            parent_data_dir = module_path.parent / "data"
            if parent_data_dir.exists():
                return parent_data_dir
            return direct_data_dir
        return Path(__file__).parent / "data"

    def load_valid_tlds(self, data_dir: Path) -> set[str]:
        tlds_file = data_dir / "tlds.txt"
        if tlds_file.exists():
            try:
                with tlds_file.open(encoding="utf-8") as handle:
                    return {line.strip().lower() for line in handle if line.strip()}
            except (OSError, ValueError) as exc:
                logger.debug("Failed to load TLD list from file: %s", exc)
        return set(self.default_tlds)

    def load_legitimate_domains(self, data_dir: Path) -> tuple[set[str], set[str]]:
        domains_file = data_dir / "legitimate_domains.json"
        if domains_file.exists():
            try:
                with domains_file.open(encoding="utf-8") as handle:
                    data = cast("dict[str, list[str]]", json.load(handle))
                    return set(data.get("legitimate_domains", [])), set(
                        data.get("legitimate_with_subdomains", [])
                    )
            except (OSError, ValueError) as exc:
                logger.debug("Failed to load legitimate domains from file: %s", exc)
        return set(), set()

    def build_reference_data(self, module_name: str) -> ExtractorReferenceData:
        data_dir = self.get_data_dir(module_name)
        legitimate_domains, legitimate_with_subdomains = self.load_legitimate_domains(data_dir)
        return ExtractorReferenceData(
            data_dir=data_dir,
            valid_tlds=self.load_valid_tlds(data_dir),
            legitimate_domains=legitimate_domains,
            legitimate_with_subdomains=legitimate_with_subdomains,
            common_file_extensions=set(self.common_file_extensions),
        )


DEFAULT_REFERENCE_DATA_POLICY = ReferenceDataPolicy(
    default_tlds=frozenset(COMMON_TLDS),
    common_file_extensions=frozenset(COMMON_FILE_EXTENSIONS),
)


@dataclass(frozen=True)
class ExtractorReferenceData:
    data_dir: Path
    valid_tlds: set[str]
    legitimate_domains: set[str]
    legitimate_with_subdomains: set[str]
    common_file_extensions: set[str]

    @classmethod
    def for_module(cls, module_name: str) -> ExtractorReferenceData:
        return DEFAULT_REFERENCE_DATA_POLICY.build_reference_data(module_name)

    def is_valid_domain(self, domain: str) -> bool:
        from iocparser.infrastructure.extractor_base import DEFAULT_DOMAIN_VALIDATION_POLICY

        return DEFAULT_DOMAIN_VALIDATION_POLICY.is_valid(
            domain,
            valid_tlds=self.valid_tlds,
            common_file_extensions=self.common_file_extensions,
            legitimate_domains=self.legitimate_domains,
            legitimate_with_subdomains=self.legitimate_with_subdomains,
        )

    def extract_domains_from_text(
        self,
        text: str,
        *,
        extract_pattern: Callable[[str, str], list[str]],
    ) -> list[str]:
        return self.extract_domains_from_urls(extract_pattern(text, "urls"))

    def extract_domains_from_urls(self, urls: list[str]) -> list[str]:
        from iocparser.shared_utils import refang_ioc

        domains: list[str] = []
        for url in urls:
            clean_url = refang_ioc(url)
            try:
                parsed = urllib.parse.urlparse(clean_url)
                if parsed.netloc:
                    domain = parsed.netloc.split(":")[0]
                    if self.is_valid_domain(domain):
                        domains.append(domain)
            except (ValueError, AttributeError) as exc:
                logger.debug("Failed to parse URL %s: %s", clean_url, exc)
        return domains


def build_reference_data(module_name: str) -> ExtractorReferenceData:
    return ExtractorReferenceData.for_module(module_name)


def defang_dotted(value: str) -> str:
    return value.replace(".", "[.]")


_DEFANG_SCHEME_PATTERNS: tuple[tuple[_re.Pattern[str], str], ...] = (
    (_re.compile(r"(?i)https://"), "hxxps://"),
    (_re.compile(r"(?i)http://"), "hxxp://"),
    (_re.compile(r"(?i)sftp://"), "sfxp://"),
    (_re.compile(r"(?i)ftp://"), "fxp://"),
)


def defang_url(url: str) -> str:
    from iocparser.shared_utils import refang_ioc

    result = refang_ioc(url)
    for pattern, replacement in _DEFANG_SCHEME_PATTERNS:
        result = pattern.sub(replacement, result)
    return defang_dotted(result)


def clean_defanged(value: str) -> str:
    return value.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
