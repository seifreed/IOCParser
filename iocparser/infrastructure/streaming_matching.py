from __future__ import annotations

from iocparser.infrastructure.utils import refang_ioc


def is_valid_match_boundary(ioc_type: str, haystack: str, start: int, end: int) -> bool:
    if ioc_type in {"domains", "hosts"}:
        if start > 0 and (haystack[start - 1].isalnum() or haystack[start - 1] in ".-"):
            return False
        return not (end < len(haystack) and (haystack[end].isalnum() or haystack[end] in ".-"))
    if ioc_type == "urls":
        if start > 0 and haystack[start - 1].isalnum():
            return False
        return not (end < len(haystack) and haystack[end] in "/._-?&=%")
    if ioc_type == "emails":
        if start > 0 and (haystack[start - 1].isalnum() or haystack[start - 1] in "._-@"):
            return False
        return not (end < len(haystack) and (haystack[end].isalnum() or haystack[end] in "._-@"))
    return True


def should_keep_ioc(
    *,
    ioc_type: str,
    chunk: str,
    ioc: str,
    prefix_length: int,
    chunk_size: int,
) -> bool:
    if prefix_length <= 0:
        return True

    candidates = (ioc, refang_ioc(ioc))
    haystacks = (chunk, chunk.lower())

    for candidate in candidates:
        if not candidate:
            continue
        normalized_candidates = {candidate, candidate.lower()}
        for haystack in haystacks:
            for needle in normalized_candidates:
                start = haystack.find(needle)
                while start != -1:
                    end = start + len(needle)
                    if (
                        (start >= prefix_length or end > prefix_length)
                        and not (prefix_length > 0 and start == 0)
                        and not (
                            end == len(haystack) and (len(haystack) - prefix_length) >= chunk_size
                        )
                        and is_valid_match_boundary(ioc_type, haystack, start, end)
                    ):
                        return True
                    start = haystack.find(needle, start + 1)
    return False
