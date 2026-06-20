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
    is_final: bool = False,
) -> bool:
    # The first chunk has no overlap prefix (prefix_length == 0) so there are no
    # leading artifacts to drop, but a match that ends exactly at a non-final
    # chunk's trailing edge may be a truncated prefix of an IOC that straddles the
    # boundary. The unified loop below defers that case (the next chunk re-presents
    # the value in full via its overlap), so the first chunk runs through it too.
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
                        (start >= prefix_length or end >= prefix_length)
                        and not (prefix_length > 0 and start == 0)
                        and not (
                            not is_final
                            and end == len(haystack)
                            and (len(haystack) - prefix_length) >= chunk_size
                        )
                        and is_valid_match_boundary(ioc_type, haystack, start, end)
                    ):
                        return True
                    start = haystack.find(needle, start + 1)
    return False
