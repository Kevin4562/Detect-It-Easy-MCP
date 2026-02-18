from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from .die_adapter import default_database_path
from .models import SearchSignaturesResult, SignatureEntry, SignatureStats


def resolve_database_root(database_root: str | None) -> Path:
    root = Path(database_root).expanduser().resolve() if database_root else default_database_path().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Database root must be an existing directory: {root}")

    # Handle nested layouts like `<root>/db/PE`.
    if not any(root.rglob("*.sg")) and (root / "db").is_dir():
        nested = (root / "db").resolve()
        if any(nested.rglob("*.sg")):
            return nested

    return root


def _parse_signature_filename(path: Path) -> tuple[str, str, int | None]:
    stem = path.stem
    priority_hint: int | None = None

    m_prio = re.match(r"^(?P<body>.+)\.(?P<prio>\d+)$", stem)
    if m_prio:
        stem = m_prio.group("body")
        priority_hint = int(m_prio.group("prio"))

    m_pref = re.match(r"^(?P<prefix>[^_]+)_(?P<name>.+)$", stem)
    if m_pref:
        category = m_pref.group("prefix")
        name = m_pref.group("name")
    else:
        category = "(none)"
        name = stem

    return category, name, priority_hint


def _iter_signature_paths(root: Path) -> Iterable[Path]:
    yield from sorted(root.rglob("*.sg"), key=lambda p: p.as_posix().lower())


def _to_entry(root: Path, path: Path) -> SignatureEntry:
    rel = path.relative_to(root)
    parts = rel.parts
    format_family = parts[0] if parts else "(root)"
    category, name, priority_hint = _parse_signature_filename(path)

    return SignatureEntry(
        format_family=format_family,
        category_prefix=category,
        signature_name=name,
        priority_hint=priority_hint,
        relative_path=rel.as_posix(),
    )


def list_signatures(
    *,
    database_root: str | None,
    format_filter: str | None,
    category_filter: str | None,
    name_contains: str | None,
    limit: int,
) -> SearchSignaturesResult:
    if limit <= 0:
        raise ValueError("limit must be > 0")

    root = resolve_database_root(database_root)

    format_filter_l = format_filter.lower() if format_filter else None
    category_filter_l = category_filter.lower() if category_filter else None
    name_contains_l = name_contains.lower() if name_contains else None

    matched: list[SignatureEntry] = []
    total = 0

    for sig_path in _iter_signature_paths(root):
        entry = _to_entry(root, sig_path)

        if format_filter_l and entry.format_family.lower() != format_filter_l:
            continue
        if category_filter_l and entry.category_prefix.lower() != category_filter_l:
            continue
        if name_contains_l and name_contains_l not in entry.signature_name.lower():
            continue

        total += 1
        if len(matched) < limit:
            matched.append(entry)

    return SearchSignaturesResult(matches=matched, total_matches=total, truncated=total > limit)


def search_signatures(
    *,
    database_root: str | None,
    query: str,
    format_filter: str | None,
    regex: bool,
    case_sensitive: bool,
    search_file_content: bool,
    limit: int,
) -> SearchSignaturesResult:
    if not query:
        raise ValueError("query must not be empty")
    if limit <= 0:
        raise ValueError("limit must be > 0")

    root = resolve_database_root(database_root)
    format_filter_l = format_filter.lower() if format_filter else None

    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(query, flags=flags) if regex else None
    query_cmp = query if case_sensitive else query.lower()

    matched: list[SignatureEntry] = []
    total = 0

    for sig_path in _iter_signature_paths(root):
        entry = _to_entry(root, sig_path)

        if format_filter_l and entry.format_family.lower() != format_filter_l:
            continue

        haystacks = [entry.relative_path, entry.signature_name, entry.category_prefix]

        is_match = False
        if pattern:
            for text in haystacks:
                if pattern.search(text):
                    is_match = True
                    break
        else:
            for text in haystacks:
                candidate = text if case_sensitive else text.lower()
                if query_cmp in candidate:
                    is_match = True
                    break

        if (not is_match) and search_file_content:
            content = sig_path.read_text(encoding="utf-8", errors="ignore")
            if pattern:
                is_match = bool(pattern.search(content))
            else:
                candidate = content if case_sensitive else content.lower()
                is_match = query_cmp in candidate

        if not is_match:
            continue

        total += 1
        if len(matched) < limit:
            matched.append(entry)

    return SearchSignaturesResult(matches=matched, total_matches=total, truncated=total > limit)


def signature_statistics(database_root: str | None) -> SignatureStats:
    root = resolve_database_root(database_root)

    by_format = Counter()
    by_prefix = Counter()
    total = 0

    for sig_path in _iter_signature_paths(root):
        entry = _to_entry(root, sig_path)
        total += 1
        by_format[entry.format_family] += 1
        by_prefix[entry.category_prefix] += 1

    return SignatureStats(
        database_root=str(root),
        total_signature_files=total,
        by_format_family=dict(sorted(by_format.items(), key=lambda item: item[0].lower())),
        by_category_prefix=dict(sorted(by_prefix.items(), key=lambda item: item[0].lower())),
    )
