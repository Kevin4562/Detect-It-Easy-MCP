from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DieVersionInfo(BaseModel):
    """Version and database metadata for die-python and the bundled DIE engine."""

    die_python_version: str = Field(..., description="Installed die-python package version.")
    die_version: str = Field(..., description="Detect It Easy engine/database version string.")
    dielib_version: str = Field(..., description="Underlying die_library version string.")
    database_path: str = Field(..., description="Resolved default DIE database path used by the bindings.")
    database_exists: bool = Field(..., description="True when the resolved default database path exists.")


class ScanFlagInfo(BaseModel):
    """Single scan flag capability and defaults."""

    name: str = Field(..., description="Stable flag name used by this MCP server.")
    bitmask_hex: str = Field(..., description="Bitmask value in hex (e.g. 0x00000001).")
    default_enabled: bool = Field(..., description="Whether this flag is enabled by default in scan tools.")
    description: str = Field(..., description="What enabling this flag does during scan.")


class DieCapabilities(BaseModel):
    """Combined capabilities response for die_get_capabilities."""

    version_info: DieVersionInfo = Field(..., description="Installed DIE runtime details.")
    scan_flags: list[ScanFlagInfo] = Field(..., description="All supported scan flags and defaults.")
    raw_output_formats: list[str] = Field(
        default_factory=lambda: ["json", "xml", "csv", "tsv", "plaintext"],
        description="Supported raw output representations for scan tools.",
    )


class DetectionRecord(BaseModel):
    """Normalized single detection entry parsed from DIE JSON output."""

    type: str = Field(..., description="Detection type (e.g. Packer, Compiler, Protector).")
    name: str = Field(..., description="Detection name (e.g. UPX, GCC, VMProtect).")
    version: str = Field(default="", description="Detected version string, if available.")
    info: str = Field(default="", description="Additional metadata from DIE (comma-separated attributes, flags, etc.).")
    display_string: str = Field(default="", description="Human-readable detection line emitted by DIE.")
    filetype: str = Field(default="", description="Container file type context for this detection (PE64, ELF64, Binary, etc.).")
    parent_file_part: str = Field(default="", description="DIE parent file part context (Header, Overlay, Resource, etc.).")
    offset: int | None = Field(default=None, description="Context offset for nested records, if present.")
    size: int | None = Field(default=None, description="Context size for nested records, if present.")
    path: list[str] = Field(
        default_factory=list,
        description="Hierarchical context path from root detect block to this value.",
    )


class ScanResult(BaseModel):
    """Normalized scan output with both raw DIE output and parsed records."""

    target: str = Field(..., description="Scanned target identifier (file path, memory label, etc.).")
    mode: str = Field(..., description="Scan mode identifier: file or memory_base64.")
    database_used: str | None = Field(default=None, description="Explicit database path passed to DIE, when used.")
    flags_applied: list[str] = Field(..., description="Enabled scan flag names sent to DIE.")
    raw_output_format: str = Field(..., description="Raw output format returned in raw_output.")
    raw_output: str = Field(default="", description="Raw text output from DIE in the requested format.")
    parsed_json: dict[str, Any] | None = Field(
        default=None,
        description="Machine-parsed JSON output from DIE. Null if JSON scan failed.",
    )
    records: list[DetectionRecord] = Field(default_factory=list, description="Flattened normalized records extracted from parsed_json.")
    record_count: int = Field(default=0, description="Number of flattened detection records.")
    type_counts: dict[str, int] = Field(default_factory=dict, description="Count of records grouped by detection type.")
    errors: list[str] = Field(default_factory=list, description="Errors observed during scan and parsing.")
    elapsed_ms: float = Field(..., description="Elapsed time for the scan workflow in milliseconds.")


class BatchScanFailure(BaseModel):
    """File-level failure entry for batch scan."""

    target: str = Field(..., description="Target file path that failed.")
    error: str = Field(..., description="Failure reason.")


class BatchScanResult(BaseModel):
    """Collection response for multi-target scans."""

    targets: list[str] = Field(..., description="Resolved list of files selected for scanning.")
    results: list[ScanResult] = Field(default_factory=list, description="Successful scan results.")
    failures: list[BatchScanFailure] = Field(default_factory=list, description="Failed scans with error details.")
    total: int = Field(..., description="Total number of targets processed.")
    succeeded: int = Field(..., description="Count of successful scans.")
    failed: int = Field(..., description="Count of failed scans.")


class CompareSummary(BaseModel):
    """High-level summary for die_compare_files."""

    left_count: int = Field(..., description="Flattened record count on left input.")
    right_count: int = Field(..., description="Flattened record count on right input.")
    shared_count: int = Field(..., description="Record signatures present in both sides.")
    left_only_count: int = Field(..., description="Record signatures unique to the left side.")
    right_only_count: int = Field(..., description="Record signatures unique to the right side.")


class CompareFilesResult(BaseModel):
    """Record-level diff between two DIE scans."""

    left_target: str = Field(..., description="Left file path.")
    right_target: str = Field(..., description="Right file path.")
    left_scan: ScanResult = Field(..., description="Full normalized scan result for the left file.")
    right_scan: ScanResult = Field(..., description="Full normalized scan result for the right file.")
    shared_records: list[DetectionRecord] = Field(default_factory=list, description="Records found on both sides (deduplicated by signature fields).")
    left_only_records: list[DetectionRecord] = Field(default_factory=list, description="Records only found on the left side.")
    right_only_records: list[DetectionRecord] = Field(default_factory=list, description="Records only found on the right side.")
    summary: CompareSummary = Field(..., description="Comparison counts.")


class SignatureEntry(BaseModel):
    """Signature file descriptor derived from DIE database tree."""

    format_family: str = Field(..., description="Top-level format folder in the database (PE, ELF, APK, etc.).")
    category_prefix: str = Field(..., description="Filename prefix before underscore (packer, protector, compiler, etc.).")
    signature_name: str = Field(..., description="Normalized signature name parsed from filename.")
    priority_hint: int | None = Field(default=None, description="Numeric priority suffix parsed from filename, if present.")
    relative_path: str = Field(..., description="Path relative to database root for this signature file.")


class SignatureStats(BaseModel):
    """Aggregate stats for signature database contents."""

    database_root: str = Field(..., description="Resolved database root used for analysis.")
    total_signature_files: int = Field(..., description="Number of .sg files discovered.")
    by_format_family: dict[str, int] = Field(default_factory=dict, description="Counts grouped by format folder.")
    by_category_prefix: dict[str, int] = Field(default_factory=dict, description="Counts grouped by prefix category.")


class EvidenceRecord(BaseModel):
    """Detection record that matched evidence filters."""

    record: DetectionRecord = Field(..., description="Underlying normalized detection record.")
    matched_type: bool = Field(..., description="True when this record matched one of requested evidence_types.")
    matched_keywords: list[str] = Field(default_factory=list, description="Keywords matched across type/name/info/string fields.")


class EvidenceResult(BaseModel):
    """Evidence-only extraction output for LLM-side packed/protection reasoning."""

    target: str = Field(..., description="Analyzed file target.")
    evidence_records: list[EvidenceRecord] = Field(default_factory=list, description="Filtered records relevant to packed/protected evidence.")
    evidence_type_counts: dict[str, int] = Field(default_factory=dict, description="Evidence record counts by detection type.")
    keyword_hits: dict[str, int] = Field(default_factory=dict, description="Matched keyword frequencies.")
    notes: list[str] = Field(default_factory=list, description="Context notes for LLM interpretation; not a packed verdict.")
    scan_result: ScanResult = Field(..., description="Full normalized scan result used as evidence source.")


class SearchSignaturesResult(BaseModel):
    """Signature search result bundle."""

    matches: list[SignatureEntry] = Field(default_factory=list, description="Matched signature entries.")
    total_matches: int = Field(..., description="Total count before truncation.")
    truncated: bool = Field(..., description="True when result list is limited by `limit`.")


class SignatureQueryResponse(BaseModel):
    """Container model for list/search responses that include resolved database root."""

    database_root: str = Field(..., description="Resolved database root used for query.")
    result: SearchSignaturesResult = Field(..., description="Search response payload.")
