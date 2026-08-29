"""Deterministic actionable evidence compiled from pre-cutoff Git diffs.

This module is intentionally pure.  Git ancestry, object reads and cutoff
enforcement stay in the repository-owned generator; this layer validates and
compiles the exact bytes supplied by that boundary.  It never reads a
repository, test patch, gold patch, provider, model or experiment result.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

ACTIONABLE_HISTORY_SOURCE_TYPE: Final = "git_commit_diff_excerpt"
_SHA40 = re.compile(r"[0-9a-f]{40}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_WORDS = re.compile(r"[A-Za-z0-9_]+")
_DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ .*? @@(?:\s?(.*))?$")
_DRIVE = re.compile(r"^[A-Za-z]:")
_MECHANICAL_SUBJECT = re.compile(
    r"^(?:TST|TEST)\b|\b(?:docs?|docstrings?|documentation|black(?:doc)?|flake8|pyupgrade|typing|changelog|"
    r"dependenc(?:y|ies)|deps)\b|\btype\s+hints?\b|\bbump\b.*\bversion\b|"
    r"\bversion\b.*\brelease\b",
    re.IGNORECASE,
)
_EXCLUDED_PARTS = frozenset(
    {
        "doc",
        "docs",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "test",
        "tests",
        "testdata",
        "testing",
    }
)
_EXCLUDED_SUFFIXES = frozenset({".md", ".rst", ".txt"})
_EXCLUDED_ROOT_FILENAMES = frozenset(
    {
        "authors",
        "changes",
        "changelog",
        "contributing",
        "history",
        "license",
        "news",
        "readme",
    }
)


class ActionableHistoryContractError(ValueError):
    """Raised when actionable history evidence cannot be closed exactly."""


def is_mechanical_history_subject(value: str) -> bool:
    """Return whether a commit subject declares non-behavioral maintenance."""

    _require_text(value, "commit_subject")
    return _MECHANICAL_SUBJECT.search(value) is not None


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes | str | object) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = _canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ActionableHistoryContractError(f"{label} must be a non-empty string")
    return value


def _require_sha40(value: object, label: str) -> str:
    if type(value) is not str or _SHA40.fullmatch(value) is None:
        raise ActionableHistoryContractError(f"{label} must be lowercase 40-hex")
    return value


def _require_path(value: str) -> str:
    if (
        not value
        or value.startswith(("/", "\\"))
        or "\\" in value
        or _DRIVE.match(value)
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
    ):
        raise ActionableHistoryContractError("diff path must be repository-relative POSIX text")
    return value


def _is_production_path(value: str) -> bool:
    path = PurePosixPath(value)
    folded = tuple(part.casefold() for part in path.parts)
    if any(part in _EXCLUDED_PARTS for part in folded):
        return False
    name = path.name.casefold()
    if len(path.parts) == 1 and name in _EXCLUDED_ROOT_FILENAMES:
        return False
    return not (
        name.startswith("test_")
        or path.suffix.casefold() in _EXCLUDED_SUFFIXES
    )


def is_actionable_production_path(value: str) -> bool:
    """Return whether one canonical repository path carries production behavior."""

    return _is_production_path(_require_path(value))


def extract_actionable_production_paths(value: CommitDiffInput) -> tuple[str, ...]:
    """Return the task-blind production paths carried by an exact Git diff."""

    if type(value) is not CommitDiffInput:
        raise ActionableHistoryContractError("path extraction requires exact CommitDiffInput")
    production_paths, _ = _parse_diff(value)
    return production_paths


@dataclass(frozen=True, slots=True)
class CommitDiffInput:
    candidate_id: str
    commit_sha: str
    parent_sha: str
    commit_subject: str
    committed_at: str
    unified_diff: str

    def __post_init__(self) -> None:
        _require_text(self.candidate_id, "candidate_id")
        _require_sha40(self.commit_sha, "commit_sha")
        _require_sha40(self.parent_sha, "parent_sha")
        _require_text(self.commit_subject, "commit_subject")
        if type(self.committed_at) is not str or _UTC.fullmatch(self.committed_at) is None:
            raise ActionableHistoryContractError("committed_at must be canonical UTC text")
        _require_text(self.unified_diff, "unified_diff")


@dataclass(frozen=True, slots=True)
class ActionableCommitEvidence:
    candidate_id: str
    commit_sha: str
    parent_sha: str
    committed_at: str
    source_type: str
    diff_sha256: str
    production_paths: tuple[str, ...]
    rendered_evidence: str
    visible_token_count: int
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class LifecycleSurvivalEvidence:
    candidate_id: str
    commit_sha: str
    base_files_sha256: str
    production_paths: tuple[str, ...]
    total_added_line_count: int
    surviving_added_line_count: int
    lifecycle_state: str
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class _Hunk:
    path: str
    symbol: str
    removed: tuple[str, ...]
    added: tuple[str, ...]


def _parse_diff(value: CommitDiffInput) -> tuple[tuple[str, ...], tuple[_Hunk, ...]]:
    paths: list[str] = []
    hunks: list[_Hunk] = []
    current_path: str | None = None
    current_symbol = ""
    removed: list[str] = []
    added: list[str] = []

    def flush() -> None:
        nonlocal removed, added
        if current_path is not None and (removed or added):
            hunks.append(_Hunk(current_path, current_symbol, tuple(removed), tuple(added)))
        removed = []
        added = []

    for line in value.unified_diff.splitlines():
        header = _DIFF_HEADER.match(line)
        if header is not None:
            flush()
            left = _require_path(header.group(1))
            right = _require_path(header.group(2))
            if left != right:
                raise ActionableHistoryContractError("renamed diff paths require a separate frozen contract")
            current_path = right
            current_symbol = ""
            paths.append(right)
            continue
        hunk_header = _HUNK_HEADER.match(line)
        if hunk_header is not None:
            flush()
            if current_path is None:
                raise ActionableHistoryContractError("diff hunk appeared before a file header")
            current_symbol = (hunk_header.group(1) or "").strip()
            continue
        if current_path is None:
            continue
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("-"):
            text = line[1:].strip()
            if text:
                removed.append(text)
        elif line.startswith("+"):
            text = line[1:].strip()
            if text:
                added.append(text)
    flush()
    if not paths or not hunks:
        raise ActionableHistoryContractError("unified diff contains no textual change hunks")
    production_paths = tuple(sorted({path for path in paths if _is_production_path(path)}))
    production_hunks = tuple(hunk for hunk in hunks if hunk.path in production_paths)
    if not production_paths or not production_hunks:
        raise ActionableHistoryContractError("commit diff contains no production evidence")
    return production_paths, production_hunks


def _terms(value: str) -> set[str]:
    return {word.casefold() for word in _WORDS.findall(value) if len(word) >= 3}


def _hunk_score(hunk: _Hunk, task_terms: set[str], subject_terms: set[str]) -> tuple[int, int, str, str]:
    evidence_terms = _terms(" ".join((hunk.path, hunk.symbol, *hunk.removed, *hunk.added)))
    task_overlap = len(task_terms & evidence_terms)
    subject_overlap = len(subject_terms & evidence_terms)
    return task_overlap, subject_overlap, hunk.path.casefold(), hunk.symbol.casefold()


def _token_count(value: str) -> int:
    return len(value.split())


def _append_if_fits(lines: list[str], candidate: list[str], token_budget: int) -> bool:
    trial = " | ".join((*lines, *candidate)).strip()
    if _token_count(trial) > token_budget:
        return False
    lines.extend(candidate)
    return True


def compile_actionable_commit_diff(
    value: CommitDiffInput,
    *,
    task_text: str,
    token_budget: int,
) -> ActionableCommitEvidence:
    """Compile a bounded, task-ranked production excerpt from exact diff bytes."""

    if type(value) is not CommitDiffInput:
        raise ActionableHistoryContractError("compiler requires exact CommitDiffInput")
    _require_text(task_text, "task_text")
    if type(token_budget) is not int or not 32 <= token_budget <= 1024:
        raise ActionableHistoryContractError("token_budget must be an exact int in [32, 1024]")
    production_paths, hunks = _parse_diff(value)
    ordered = tuple(
        sorted(
            hunks,
            key=lambda item: _hunk_score(item, _terms(task_text), _terms(value.commit_subject)),
            reverse=True,
        )
    )
    lines = [
        f"SUBJECT: {value.commit_subject}",
        f"COMMIT: {value.commit_sha}",
        f"CHANGED PRODUCTION PATHS: {', '.join(production_paths[:6])}",
    ]
    if _token_count(" | ".join(lines)) > token_budget:
        raise ActionableHistoryContractError("token budget cannot hold the required evidence header")
    emitted = 0
    for hunk in ordered:
        block = [f"FILE: {hunk.path}", f"SYMBOL: {hunk.symbol or 'MODULE'}"]
        block.extend(f"- {line}" for line in hunk.removed[:4])
        block.extend(f"+ {line}" for line in hunk.added[:6])
        if _append_if_fits(lines, block, token_budget):
            emitted += 1
            continue
        minimal = [f"FILE: {hunk.path}", f"SYMBOL: {hunk.symbol or 'MODULE'}"]
        if emitted == 0 and not _append_if_fits(lines, minimal, token_budget):
            raise ActionableHistoryContractError("token budget cannot hold one production hunk identity")
        break
    rendered = " | ".join(lines).strip()
    fields = {
        "schema": "cp2-137-actionable-commit-evidence-v1",
        "candidate_id": value.candidate_id,
        "commit_sha": value.commit_sha,
        "parent_sha": value.parent_sha,
        "committed_at": value.committed_at,
        "source_type": ACTIONABLE_HISTORY_SOURCE_TYPE,
        "diff_sha256": _sha256(value.unified_diff),
        "production_paths": list(production_paths),
        "rendered_evidence": rendered,
        "visible_token_count": _token_count(rendered),
    }
    return ActionableCommitEvidence(
        candidate_id=value.candidate_id,
        commit_sha=value.commit_sha,
        parent_sha=value.parent_sha,
        committed_at=value.committed_at,
        source_type=ACTIONABLE_HISTORY_SOURCE_TYPE,
        diff_sha256=fields["diff_sha256"],
        production_paths=production_paths,
        rendered_evidence=rendered,
        visible_token_count=fields["visible_token_count"],
        identity_sha256=_sha256(fields),
    )


def derive_lifecycle_from_base_survival(
    value: CommitDiffInput,
    *,
    base_files: Mapping[str, str],
) -> LifecycleSurvivalEvidence:
    """Classify lifecycle from exact survival of added production lines at cutoff."""

    if type(value) is not CommitDiffInput:
        raise ActionableHistoryContractError("lifecycle derivation requires exact CommitDiffInput")
    if not isinstance(base_files, Mapping) or any(
        type(path) is not str or type(content) is not str for path, content in base_files.items()
    ):
        raise ActionableHistoryContractError("base_files must map exact path strings to text")
    production_paths, hunks = _parse_diff(value)
    if set(base_files) != set(production_paths):
        raise ActionableHistoryContractError("base_files must cover every and only production diff path")
    added = tuple(line for hunk in hunks for line in hunk.added)
    if not added:
        raise ActionableHistoryContractError("lifecycle derivation requires added production lines")
    base_lines = {
        path: {line.strip() for line in content.splitlines() if line.strip()}
        for path, content in base_files.items()
    }
    surviving = sum(line in base_lines[hunk.path] for hunk in hunks for line in hunk.added)
    if surviving == len(added):
        state = "active"
    elif surviving == 0:
        state = "superseded"
    else:
        state = "unresolved"
    base_files_sha256 = _sha256({path: base_files[path] for path in sorted(base_files)})
    fields = {
        "schema": "cp2-137-lifecycle-line-survival-v1",
        "candidate_id": value.candidate_id,
        "commit_sha": value.commit_sha,
        "base_files_sha256": base_files_sha256,
        "production_paths": list(production_paths),
        "total_added_line_count": len(added),
        "surviving_added_line_count": surviving,
        "lifecycle_state": state,
    }
    return LifecycleSurvivalEvidence(
        candidate_id=value.candidate_id,
        commit_sha=value.commit_sha,
        base_files_sha256=base_files_sha256,
        production_paths=production_paths,
        total_added_line_count=len(added),
        surviving_added_line_count=surviving,
        lifecycle_state=state,
        identity_sha256=_sha256(fields),
    )


__all__ = [
    "ACTIONABLE_HISTORY_SOURCE_TYPE",
    "ActionableCommitEvidence",
    "ActionableHistoryContractError",
    "CommitDiffInput",
    "LifecycleSurvivalEvidence",
    "compile_actionable_commit_diff",
    "derive_lifecycle_from_base_survival",
    "extract_actionable_production_paths",
    "is_actionable_production_path",
    "is_mechanical_history_subject",
]
