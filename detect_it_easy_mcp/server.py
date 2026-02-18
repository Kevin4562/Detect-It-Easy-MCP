from __future__ import annotations

from collections import Counter
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .die_adapter import (
    ScanRequest,
    decode_base64_payload,
    detection_signature,
    get_scan_flag_info,
    get_version_info,
    run_file_scan,
    run_memory_scan,
)
from .models import (
    BatchScanFailure,
    BatchScanResult,
    CompareFilesResult,
    CompareSummary,
    DetectionRecord,
    DieCapabilities,
    EvidenceRecord,
    EvidenceResult,
    ScanResult,
    SearchSignaturesResult,
    SignatureEntry,
    SignatureStats,
)
from .signatures import list_signatures, search_signatures, signature_statistics

mcp = FastMCP("detect-it-easy-mcp")


def _scan_request_from_args(
    *,
    deep_scan: bool,
    heuristic_scan: bool,
    all_types_scan: bool,
    recursive_scan: bool,
    verbose: bool,
    aggressive_scan: bool,
    overlay_scan: bool,
    resources_scan: bool,
    archives_scan: bool,
    use_cache: bool,
    format_result: bool,
) -> ScanRequest:
    return ScanRequest(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )


def _record_key(record: DetectionRecord) -> tuple[str, str, str, str, str]:
    return detection_signature(record)


def _unique_records(records: list[DetectionRecord]) -> dict[tuple[str, str, str, str, str], DetectionRecord]:
    result: dict[tuple[str, str, str, str, str], DetectionRecord] = {}
    for rec in records:
        key = _record_key(rec)
        if key not in result:
            result[key] = rec
    return result


def _resolve_batch_targets(
    *,
    file_paths: list[str] | None,
    root_dir: str | None,
    glob_pattern: str,
    recurse_dirs: bool,
    max_files: int,
) -> list[Path]:
    if max_files <= 0:
        raise ValueError("max_files must be > 0")

    resolved: list[Path] = []

    if file_paths:
        for fp in file_paths:
            p = Path(fp).expanduser().resolve()
            if p.exists() and p.is_file():
                resolved.append(p)
            else:
                raise ValueError(f"Invalid batch file path: {p}")

    if root_dir:
        root = Path(root_dir).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Invalid root_dir: {root}")

        iterator = root.rglob(glob_pattern) if recurse_dirs else root.glob(glob_pattern)
        for p in iterator:
            if p.is_file():
                resolved.append(p.resolve())

    deduped: list[Path] = []
    seen: set[Path] = set()
    for p in resolved:
        if p not in seen:
            seen.add(p)
            deduped.append(p)

    return deduped[:max_files]


@mcp.tool()
def die_get_capabilities() -> DieCapabilities:
    """
    Return Detect It Easy runtime metadata and supported scan flags.

    Use this first to discover:
    - Installed die-python / DIE engine versions
    - Resolved database path and availability
    - Full scan flag list, bitmasks, and default settings
    - Supported raw output formats for scan tools
    """

    return DieCapabilities(version_info=get_version_info(), scan_flags=get_scan_flag_info())


@mcp.tool()
def die_scan_file(
    file_path: str,
    database_path: str | None = None,
    deep_scan: bool = True,
    heuristic_scan: bool = True,
    all_types_scan: bool = False,
    recursive_scan: bool = False,
    verbose: bool = False,
    aggressive_scan: bool = False,
    overlay_scan: bool = False,
    resources_scan: bool = False,
    archives_scan: bool = False,
    use_cache: bool = False,
    format_result: bool = False,
    raw_output_format: str = "json",
) -> ScanResult:
    """
    Scan one file with Detect It Easy and return normalized + raw results.

    How to use:
    - Provide `file_path` as an absolute or relative local file path.
    - Optionally set `database_path` to a custom DIE database directory.
    - Choose scan behavior with flags (`deep_scan`, `heuristic_scan`, etc.).
    - Choose `raw_output_format` in: json, xml, csv, tsv, plaintext.

    Inputs:
    - file_path: local file path to analyze.
    - database_path: optional directory containing DIE signatures.
    - scan flags: booleans mapped directly to DIE bitmask flags.
    - raw_output_format: requested raw output representation.

    Output:
    - `ScanResult` with raw DIE output, parsed JSON tree, flattened records,
      grouped type counts, and errors.
    """

    req = _scan_request_from_args(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )

    return run_file_scan(
        file_path=file_path,
        database_path=database_path,
        scan_request=req,
        raw_output_format=raw_output_format,
    )


@mcp.tool()
def die_scan_memory_base64(
    data_base64: str,
    label: str = "memory_payload",
    database_path: str | None = None,
    deep_scan: bool = True,
    heuristic_scan: bool = True,
    all_types_scan: bool = False,
    recursive_scan: bool = False,
    verbose: bool = False,
    aggressive_scan: bool = False,
    overlay_scan: bool = False,
    resources_scan: bool = False,
    archives_scan: bool = False,
    use_cache: bool = False,
    format_result: bool = False,
    raw_output_format: str = "json",
) -> ScanResult:
    """
    Scan raw bytes (base64-encoded) using direct DIE memory bindings.

    How to use:
    - Base64-encode binary bytes and pass as `data_base64`.
    - Set an optional `label` to identify this payload in output.
    - Use the same flags and output format controls as file scans.

    Inputs:
    - data_base64: required base64 payload (validated).
    - label: human-readable identifier for the target.
    - database_path + scan flags + raw_output_format: same semantics as die_scan_file.

    Output:
    - `ScanResult` equivalent to file scans, but mode is `memory_base64`.
    """

    payload = decode_base64_payload(data_base64)
    req = _scan_request_from_args(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )

    return run_memory_scan(
        data=payload,
        label=label,
        database_path=database_path,
        scan_request=req,
        raw_output_format=raw_output_format,
    )


@mcp.tool()
def die_scan_batch(
    file_paths: list[str] | None = None,
    root_dir: str | None = None,
    glob_pattern: str = "*",
    recurse_dirs: bool = False,
    max_files: int = 200,
    database_path: str | None = None,
    deep_scan: bool = True,
    heuristic_scan: bool = True,
    all_types_scan: bool = False,
    recursive_scan: bool = False,
    verbose: bool = False,
    aggressive_scan: bool = False,
    overlay_scan: bool = False,
    resources_scan: bool = False,
    archives_scan: bool = False,
    use_cache: bool = False,
    format_result: bool = False,
    raw_output_format: str = "json",
) -> BatchScanResult:
    """
    Scan multiple files in one call and return per-target results.

    How to use:
    - Provide explicit `file_paths`, or scan a `root_dir` with `glob_pattern`.
    - Enable `recurse_dirs` for recursive file collection under root_dir.
    - Control workload size with `max_files`.
    - Same DIE scan flags as single-file scan.

    Inputs:
    - file_paths: explicit list of files.
    - root_dir/glob_pattern/recurse_dirs: optional discovery mode.
    - max_files: hard limit after dedupe.
    - database_path + scan flags + raw_output_format.

    Output:
    - `BatchScanResult` with successes and explicit file-level failures.
    """

    req = _scan_request_from_args(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )

    targets = _resolve_batch_targets(
        file_paths=file_paths,
        root_dir=root_dir,
        glob_pattern=glob_pattern,
        recurse_dirs=recurse_dirs,
        max_files=max_files,
    )

    results: list[ScanResult] = []
    failures: list[BatchScanFailure] = []

    for target in targets:
        try:
            scan = run_file_scan(
                file_path=str(target),
                database_path=database_path,
                scan_request=req,
                raw_output_format=raw_output_format,
            )
            results.append(scan)
        except Exception as exc:  # pragma: no cover - exercised in negative path tests
            failures.append(BatchScanFailure(target=str(target), error=str(exc)))

    return BatchScanResult(
        targets=[str(t) for t in targets],
        results=results,
        failures=failures,
        total=len(targets),
        succeeded=len(results),
        failed=len(failures),
    )


@mcp.tool()
def die_compare_files(
    left_file_path: str,
    right_file_path: str,
    database_path: str | None = None,
    deep_scan: bool = True,
    heuristic_scan: bool = True,
    all_types_scan: bool = False,
    recursive_scan: bool = False,
    verbose: bool = False,
    aggressive_scan: bool = False,
    overlay_scan: bool = False,
    resources_scan: bool = False,
    archives_scan: bool = False,
    use_cache: bool = False,
    format_result: bool = False,
    raw_output_format: str = "json",
) -> CompareFilesResult:
    """
    Compare normalized DIE detection records between two files.

    How to use:
    - Provide two file paths.
    - Use same scan-flag semantics as die_scan_file.

    Output includes:
    - full scan results for both sides
    - shared records
    - left-only and right-only records
    - count summary
    """

    req = _scan_request_from_args(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )

    left_scan = run_file_scan(
        file_path=left_file_path,
        database_path=database_path,
        scan_request=req,
        raw_output_format=raw_output_format,
    )
    right_scan = run_file_scan(
        file_path=right_file_path,
        database_path=database_path,
        scan_request=req,
        raw_output_format=raw_output_format,
    )

    left_map = _unique_records(left_scan.records)
    right_map = _unique_records(right_scan.records)

    shared_keys = set(left_map).intersection(right_map)
    left_only_keys = set(left_map).difference(right_map)
    right_only_keys = set(right_map).difference(left_map)

    shared_records = [left_map[k] for k in sorted(shared_keys)]
    left_only_records = [left_map[k] for k in sorted(left_only_keys)]
    right_only_records = [right_map[k] for k in sorted(right_only_keys)]

    summary = CompareSummary(
        left_count=len(left_scan.records),
        right_count=len(right_scan.records),
        shared_count=len(shared_records),
        left_only_count=len(left_only_records),
        right_only_count=len(right_only_records),
    )

    return CompareFilesResult(
        left_target=left_scan.target,
        right_target=right_scan.target,
        left_scan=left_scan,
        right_scan=right_scan,
        shared_records=shared_records,
        left_only_records=left_only_records,
        right_only_records=right_only_records,
        summary=summary,
    )


@mcp.tool()
def die_extract_evidence(
    file_path: str,
    database_path: str | None = None,
    evidence_types: list[str] | None = None,
    keywords: list[str] | None = None,
    deep_scan: bool = True,
    heuristic_scan: bool = True,
    all_types_scan: bool = False,
    recursive_scan: bool = False,
    verbose: bool = False,
    aggressive_scan: bool = False,
    overlay_scan: bool = False,
    resources_scan: bool = False,
    archives_scan: bool = False,
    use_cache: bool = False,
    format_result: bool = False,
    raw_output_format: str = "json",
) -> EvidenceResult:
    """
    Extract packed/protection-relevant evidence records without making a verdict.

    This tool is intentionally evidence-only. It does NOT return a packed boolean.
    It provides filtered detection records so the LLM can determine packed/protected
    status using context-sensitive reasoning.

    How to use:
    - Optionally pass `evidence_types` (case-insensitive exact type names).
    - Optionally pass `keywords` searched across type/name/version/info/display text.
    - Omit both to use pragmatic defaults focused on protection/packing indicators.

    Output:
    - matching evidence records
    - grouped evidence type counts
    - keyword hit frequencies
    - notes clarifying this is not a final determination
    - full underlying ScanResult for transparency
    """

    req = _scan_request_from_args(
        deep_scan=deep_scan,
        heuristic_scan=heuristic_scan,
        all_types_scan=all_types_scan,
        recursive_scan=recursive_scan,
        verbose=verbose,
        aggressive_scan=aggressive_scan,
        overlay_scan=overlay_scan,
        resources_scan=resources_scan,
        archives_scan=archives_scan,
        use_cache=use_cache,
        format_result=format_result,
    )

    scan_result = run_file_scan(
        file_path=file_path,
        database_path=database_path,
        scan_request=req,
        raw_output_format=raw_output_format,
    )

    effective_types = evidence_types or [
        "packer",
        "protector",
        "protection",
        "crypter",
        "cryptor",
        "compressor",
        "obfuscator",
        ".net compressor",
        ".net obfuscator",
        "apk obfuscator",
        "jar obfuscator",
        "virtual machine",
        "overlay",
        "sfx",
        "dongle protection",
        "joiner",
    ]
    effective_keywords = keywords or [
        "packed",
        "packer",
        "upx",
        "mpress",
        "aspack",
        "themida",
        "vmprotect",
        "enigma",
        "obfus",
        "crypter",
        "cryptor",
        "protect",
    ]

    type_set = {t.strip().lower() for t in effective_types if t.strip()}
    keyword_list = [k.strip().lower() for k in effective_keywords if k.strip()]

    evidence_records: list[EvidenceRecord] = []
    type_counts = Counter()
    keyword_hits = Counter()

    for rec in scan_result.records:
        rec_type_l = rec.type.strip().lower()
        searchable = "\n".join([rec.type, rec.name, rec.version, rec.info, rec.display_string]).lower()

        matched_type = rec_type_l in type_set if type_set else False
        matched_keywords: list[str] = []
        for keyword in keyword_list:
            if keyword in searchable:
                matched_keywords.append(keyword)

        if matched_type or matched_keywords:
            evidence_records.append(
                EvidenceRecord(record=rec, matched_type=matched_type, matched_keywords=matched_keywords)
            )
            type_counts[rec.type or "Unknown"] += 1
            for keyword in matched_keywords:
                keyword_hits[keyword] += 1

    notes = [
        "This tool returns evidence only and does not classify the file as packed/protected.",
        "Use evidence_records with surrounding context to make LLM-side determinations.",
    ]

    return EvidenceResult(
        target=scan_result.target,
        evidence_records=evidence_records,
        evidence_type_counts=dict(sorted(type_counts.items(), key=lambda item: item[0].lower())),
        keyword_hits=dict(sorted(keyword_hits.items(), key=lambda item: item[0])),
        notes=notes,
        scan_result=scan_result,
    )


@mcp.tool()
def die_list_signatures(
    database_root: str | None = None,
    format_filter: str | None = None,
    category_filter: str | None = None,
    name_contains: str | None = None,
    limit: int = 200,
) -> list[SignatureEntry]:
    """
    List DIE signature files from the database with optional filtering.

    How to use:
    - Use `format_filter` for top-level families like PE, ELF, MACH, APK.
    - Use `category_filter` for prefixes like packer/protector/compiler.
    - Use `name_contains` for substring filtering.
    - Use `limit` to cap returned rows.

    Output:
    - List of structured signature entries (path, category, priority hint).
    """

    return list_signatures(
        database_root=database_root,
        format_filter=format_filter,
        category_filter=category_filter,
        name_contains=name_contains,
        limit=limit,
    ).matches


@mcp.tool()
def die_search_signatures(
    query: str,
    database_root: str | None = None,
    format_filter: str | None = None,
    regex: bool = False,
    case_sensitive: bool = False,
    search_file_content: bool = False,
    limit: int = 200,
) -> SearchSignaturesResult:
    """
    Search DIE signatures by path/name/category and optional file-content scan.

    How to use:
    - `query` is required.
    - Set `regex=true` for regular-expression matching.
    - Set `search_file_content=true` to search inside signature script files.
    - Use `format_filter` and `limit` to focus scope.

    Output:
    - Matches, total count before truncation, and truncation status.
    """

    return search_signatures(
        database_root=database_root,
        query=query,
        format_filter=format_filter,
        regex=regex,
        case_sensitive=case_sensitive,
        search_file_content=search_file_content,
        limit=limit,
    )


@mcp.tool()
def die_signature_statistics(database_root: str | None = None) -> SignatureStats:
    """
    Return aggregate statistics over DIE `.sg` signature files.

    Output includes:
    - total signature count
    - counts by format family (PE, ELF, ...)
    - counts by category prefix (packer, protector, ...)
    """

    return signature_statistics(database_root)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
