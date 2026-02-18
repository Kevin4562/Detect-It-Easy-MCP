from __future__ import annotations

import base64
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import die

from .models import DetectionRecord, DieVersionInfo, ScanFlagInfo, ScanResult


# Core C API flags from die.h and XScanEngine.
FLAG_DEFINITIONS: dict[str, tuple[int, bool, str]] = {
    "deep_scan": (0x00000001, True, "Enable deeper signature inspection."),
    "heuristic_scan": (0x00000002, True, "Enable heuristic detection routines."),
    "all_types_scan": (0x00000004, False, "Scan all supported file types instead of limiting by initial type."),
    "recursive_scan": (0x00000008, False, "Enable recursive detection for nested containers/objects."),
    "verbose": (0x00000010, False, "Enable verbose details in plain-text style output."),
    "aggressive_scan": (0x00000020, False, "Enable aggressive scan mode for broader matching."),
    "overlay_scan": (0x00000040, False, "Enable dedicated overlay scanning."),
    "resources_scan": (0x00000080, False, "Enable resources section scanning."),
    "archives_scan": (0x00000100, False, "Enable archive scanning logic."),
    "use_cache": (0x01000000, False, "Allow engine cache usage where supported."),
    "format_result": (0x10000000, False, "Enable formatted output behavior in DIE engine."),
}

RESULT_FORMAT_FLAGS: dict[str, int] = {
    "json": 0x00020000,
    "xml": 0x00010000,
    "tsv": 0x00040000,
    "csv": 0x00080000,
    "plaintext": 0,
}


@dataclass(frozen=True)
class ScanRequest:
    deep_scan: bool = True
    heuristic_scan: bool = True
    all_types_scan: bool = False
    recursive_scan: bool = False
    verbose: bool = False
    aggressive_scan: bool = False
    overlay_scan: bool = False
    resources_scan: bool = False
    archives_scan: bool = False
    use_cache: bool = False
    format_result: bool = False


@dataclass(frozen=True)
class _ParseContext:
    filetype: str = ""
    parent_file_part: str = ""
    offset: int | None = None
    size: int | None = None
    path: tuple[str, ...] = ()


def default_database_path() -> Path:
    """
    Resolve die-python database path robustly across layout variants.

    Some builds place signatures at `.../die/db/PE`, while others use
    `.../die/db/db/PE`. This returns the directory that directly contains PE.
    """

    base = Path(str(die.database_path))
    if (base / "PE").exists():
        return base
    if (base / "db" / "PE").exists():
        return base / "db"
    return base


def get_version_info() -> DieVersionInfo:
    import importlib.metadata

    try:
        die_python_version = importlib.metadata.version("die-python")
    except importlib.metadata.PackageNotFoundError:
        die_python_version = "unknown"

    db_path = default_database_path()
    return DieVersionInfo(
        die_python_version=die_python_version,
        die_version=str(die.die_version),
        dielib_version=str(die.dielib_version),
        database_path=str(db_path),
        database_exists=db_path.exists(),
    )


def get_scan_flag_info() -> list[ScanFlagInfo]:
    result: list[ScanFlagInfo] = []
    for name, (mask, default_enabled, description) in FLAG_DEFINITIONS.items():
        result.append(
            ScanFlagInfo(
                name=name,
                bitmask_hex=f"0x{mask:08X}",
                default_enabled=default_enabled,
                description=description,
            )
        )
    return result


def decode_base64_payload(data_base64: str) -> bytes:
    try:
        return base64.b64decode(data_base64, validate=True)
    except Exception as exc:  # pragma: no cover - exhaustive error text not critical
        raise ValueError(f"Invalid base64 payload: {exc}") from exc


def _build_flags(request: ScanRequest, raw_output_format: str) -> tuple[int, list[str]]:
    if raw_output_format not in RESULT_FORMAT_FLAGS:
        raise ValueError(f"Unsupported raw_output_format: {raw_output_format}")

    flags = 0
    enabled: list[str] = []

    for name, (mask, _default, _description) in FLAG_DEFINITIONS.items():
        if getattr(request, name):
            flags |= mask
            enabled.append(name)

    format_mask = RESULT_FORMAT_FLAGS[raw_output_format]
    if format_mask:
        flags |= format_mask
        enabled.append(f"result_as_{raw_output_format}")

    return flags, enabled


def _resolve_database(database_path: str | None) -> str | None:
    if database_path is None:
        db = default_database_path()
        if not db.exists():
            raise ValueError(f"Default DIE database path does not exist: {db}")
        return str(db)

    db = Path(database_path).expanduser().resolve()
    if not db.exists() or not db.is_dir():
        raise ValueError(f"Database path must be an existing directory: {db}")

    # Requirement: only call load_database for explicit, validated database paths.
    loaded = die.load_database(str(db))
    if loaded == 0:
        raise ValueError(f"DIE failed to load explicit database path: {db}")

    return str(db)


def _scan_file_raw(file_path: Path, flags: int, database: str | None) -> str:
    result = die.scan_file(str(file_path), flags, database=database)
    if result is None:
        raise RuntimeError("die.scan_file returned no result")
    return result


def _scan_memory_raw(memory: bytes, flags: int, database: str | None) -> str:
    result = die.scan_memory(memory, flags, database=database)
    if result is None:
        raise RuntimeError("die.scan_memory returned no result")
    return result


def _extract_json_errors(parsed_json: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for err in parsed_json.get("errors", []):
        if isinstance(err, dict):
            script = str(err.get("script", "")).strip()
            err_text = str(err.get("errorString", "")).strip()
            if script and err_text:
                errors.append(f"{script}: {err_text}")
            elif err_text:
                errors.append(err_text)
    return errors


def _append_path(path: tuple[str, ...], node: dict[str, Any]) -> tuple[str, ...]:
    markers: list[str] = []
    filetype = str(node.get("filetype", "")).strip()
    parent_part = str(node.get("parentfilepart", "")).strip()
    if filetype:
        markers.append(filetype)
    if parent_part:
        markers.append(parent_part)
    if markers:
        return path + tuple(markers)
    return path


def _flatten_detects(node: Any, ctx: _ParseContext, out: list[DetectionRecord]) -> None:
    if isinstance(node, list):
        for item in node:
            _flatten_detects(item, ctx, out)
        return

    if not isinstance(node, dict):
        return

    next_ctx = _ParseContext(
        filetype=str(node.get("filetype", ctx.filetype) or ctx.filetype),
        parent_file_part=str(node.get("parentfilepart", ctx.parent_file_part) or ctx.parent_file_part),
        offset=_to_int_or_none(node.get("offset", ctx.offset)),
        size=_to_int_or_none(node.get("size", ctx.size)),
        path=_append_path(ctx.path, node),
    )

    is_leaf = "type" in node and "name" in node
    if is_leaf:
        type_value = str(node.get("type", "")).strip()
        name_value = str(node.get("name", "")).strip()
        version_value = str(node.get("version", "")).strip()
        info_value = str(node.get("info", "")).strip()
        display_value = str(node.get("string", "")).strip()
        leaf_path = list(next_ctx.path)
        if type_value or name_value:
            leaf_path.append(f"{type_value}:{name_value}".strip(":"))

        out.append(
            DetectionRecord(
                type=type_value,
                name=name_value,
                version=version_value,
                info=info_value,
                display_string=display_value,
                filetype=next_ctx.filetype,
                parent_file_part=next_ctx.parent_file_part,
                offset=next_ctx.offset,
                size=next_ctx.size,
                path=leaf_path,
            )
        )

    for key in ("detects", "values"):
        value = node.get(key)
        if isinstance(value, list):
            for child in value:
                _flatten_detects(child, next_ctx, out)


def _to_int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        try:
            return int(value, 10)
        except ValueError:
            return None
    return None


def _parse_json_output(raw_json: str) -> tuple[dict[str, Any] | None, list[DetectionRecord], list[str]]:
    errors: list[str] = []
    try:
        parsed = json.loads(raw_json)
    except Exception as exc:
        return None, [], [f"Failed to parse DIE JSON output: {exc}"]

    if not isinstance(parsed, dict):
        return None, [], ["DIE JSON output is not an object"]

    records: list[DetectionRecord] = []
    _flatten_detects(parsed.get("detects", []), _ParseContext(), records)
    errors.extend(_extract_json_errors(parsed))

    return parsed, records, errors


def _record_type_counts(records: list[DetectionRecord]) -> dict[str, int]:
    counts = Counter()
    for rec in records:
        key = rec.type if rec.type else "Unknown"
        counts[key] += 1
    return dict(sorted(counts.items(), key=lambda item: item[0].lower()))


def _finalize_scan_result(
    *,
    target: str,
    mode: str,
    database_used: str | None,
    flags_applied: list[str],
    raw_output_format: str,
    raw_output: str,
    json_output: str,
    elapsed_ms: float,
    base_errors: list[str] | None = None,
) -> ScanResult:
    errors = list(base_errors or [])
    parsed_json, records, parse_errors = _parse_json_output(json_output)
    errors.extend(parse_errors)

    result = ScanResult(
        target=target,
        mode=mode,
        database_used=database_used,
        flags_applied=flags_applied,
        raw_output_format=raw_output_format,
        raw_output=raw_output,
        parsed_json=parsed_json,
        records=records,
        record_count=len(records),
        type_counts=_record_type_counts(records),
        errors=errors,
        elapsed_ms=elapsed_ms,
    )
    return result


def run_file_scan(
    *,
    file_path: str,
    database_path: str | None,
    scan_request: ScanRequest,
    raw_output_format: str,
) -> ScanResult:
    target = Path(file_path).expanduser().resolve()
    if not target.exists() or not target.is_file():
        raise ValueError(f"Invalid file path: {target}")

    database = _resolve_database(database_path)

    json_flags, enabled_flags = _build_flags(scan_request, "json")
    raw_flags, _ = _build_flags(scan_request, raw_output_format)

    start = time.perf_counter()
    json_output = _scan_file_raw(target, json_flags, database)
    raw_output = json_output if raw_output_format == "json" else _scan_file_raw(target, raw_flags, database)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    return _finalize_scan_result(
        target=str(target),
        mode="file",
        database_used=database,
        flags_applied=enabled_flags,
        raw_output_format=raw_output_format,
        raw_output=raw_output,
        json_output=json_output,
        elapsed_ms=elapsed_ms,
    )


def run_memory_scan(
    *,
    data: bytes,
    label: str,
    database_path: str | None,
    scan_request: ScanRequest,
    raw_output_format: str,
) -> ScanResult:
    if not data:
        raise ValueError("Memory payload is empty")

    database = _resolve_database(database_path)

    json_flags, enabled_flags = _build_flags(scan_request, "json")
    raw_flags, _ = _build_flags(scan_request, raw_output_format)

    start = time.perf_counter()
    json_output = _scan_memory_raw(data, json_flags, database)
    raw_output = json_output if raw_output_format == "json" else _scan_memory_raw(data, raw_flags, database)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    return _finalize_scan_result(
        target=label,
        mode="memory_base64",
        database_used=database,
        flags_applied=enabled_flags,
        raw_output_format=raw_output_format,
        raw_output=raw_output,
        json_output=json_output,
        elapsed_ms=elapsed_ms,
    )


def detection_signature(record: DetectionRecord) -> tuple[str, str, str, str, str]:
    """Stable tuple key used for compare/dedupe operations."""

    return (
        record.type.strip().lower(),
        record.name.strip().lower(),
        record.version.strip().lower(),
        record.info.strip().lower(),
        record.filetype.strip().lower(),
    )
