"""Canonical Native Sidecar behavior receipts for Continuum."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

_SHA40: Final = re.compile(r"[0-9a-f]{40}")
_SHA64: Final = re.compile(r"[0-9a-f]{64}")
_UTC: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_REPOSITORY: Final = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_RELATIONS: Final = frozenset({"supports", "supersedes", "reverts", "revokes", "conflicts"})
_SHELL_TOKENS: Final = (";", "&&", "||", "`", "$(", "\n", "\r")


class NativeSidecarContractError(ValueError):
    """Raised when a Native Sidecar receipt cannot be closed exactly."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes | object) -> str:
    payload = value if isinstance(value, bytes) else _canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def _sha(value: object, length: int, label: str) -> str:
    pattern = _SHA40 if length == 40 else _SHA64
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise NativeSidecarContractError(f"{label} must be lowercase {length}-hex")
    return value


def _path(value: object) -> str:
    if type(value) is not str or not value or value.startswith(("/", "\\")) or "\\" in value:
        raise NativeSidecarContractError("path must be repository-relative POSIX text")
    if any(part in {"", ".", ".."} for part in PurePosixPath(value).parts):
        raise NativeSidecarContractError("path escaped the repository")
    return value


@dataclass(frozen=True, slots=True)
class NativeBehaviorEvidence:
    command_argv: tuple[str, ...]
    environment_sha256: str
    test_patch_sha256: str
    changed_test_paths: tuple[str, ...]
    parent_test_patch_applied: bool
    setup_succeeded: bool
    setup_stdout_sha256: str
    setup_stderr_sha256: str
    parent_returncode: int
    parent_stdout_sha256: str
    parent_stderr_sha256: str
    current_returncode: int
    current_stdout_sha256: str
    current_stderr_sha256: str


@dataclass(frozen=True, slots=True)
class NativeSidecarInput:
    repository: str
    commit_sha: str
    parent_sha: str
    tree_sha: str
    subject: str
    committed_at: str
    observed_at: str
    production_paths: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    api_delta: tuple[str, ...]
    lifecycle_relation: str
    related_record_ids: tuple[str, ...]
    behavior_evidence: NativeBehaviorEvidence | None
    profile_sha256: str


@dataclass(frozen=True, slots=True)
class NativeSidecarReceipt:
    schema_version: str
    repository: str
    commit_sha: str
    parent_sha: str
    tree_sha: str
    subject: str
    committed_at: str
    observed_at: str
    production_paths: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    api_delta: tuple[str, ...]
    lifecycle_relation: str
    related_record_ids: tuple[str, ...]
    behavior_status: str
    behavior_verified: bool
    command_identity_sha256: str | None
    behavior_evidence: NativeBehaviorEvidence | None
    profile_sha256: str
    canonical_bytes: bytes
    canonical_sha256: str
    identity_sha256: str


def _validate_evidence(value: NativeBehaviorEvidence) -> str:
    if type(value) is not NativeBehaviorEvidence:
        raise NativeSidecarContractError("behavior evidence requires exact typed value")
    if type(value.command_argv) is not tuple or not value.command_argv:
        raise NativeSidecarContractError("command argv requires a non-empty tuple")
    for argument in value.command_argv:
        if type(argument) is not str or not argument or any(token in argument for token in _SHELL_TOKENS):
            raise NativeSidecarContractError("command argv contains shell syntax or invalid text")
    for label in (
        "environment_sha256",
        "test_patch_sha256",
        "parent_stdout_sha256",
        "parent_stderr_sha256",
        "current_stdout_sha256",
        "current_stderr_sha256",
        "setup_stdout_sha256",
        "setup_stderr_sha256",
    ):
        _sha(getattr(value, label), 64, label)
    if type(value.changed_test_paths) is not tuple or not value.changed_test_paths:
        raise NativeSidecarContractError("behavior evidence requires changed tests")
    tuple(_path(path) for path in value.changed_test_paths)
    if type(value.parent_test_patch_applied) is not bool or type(value.setup_succeeded) is not bool:
        raise NativeSidecarContractError("patch/setup flags require exact bool")
    for label in ("parent_returncode", "current_returncode"):
        if type(getattr(value, label)) is not int:
            raise NativeSidecarContractError(f"{label} requires exact int")
    return _sha256({"command_argv": list(value.command_argv)})


def compile_native_sidecar_receipt(value: NativeSidecarInput) -> NativeSidecarReceipt:
    if type(value) is not NativeSidecarInput:
        raise NativeSidecarContractError("receipt input requires exact typed value")
    if type(value.repository) is not str or _REPOSITORY.fullmatch(value.repository) is None:
        raise NativeSidecarContractError("repository must be owner/name text")
    commit = _sha(value.commit_sha, 40, "commit_sha")
    parent = _sha(value.parent_sha, 40, "parent_sha")
    tree = _sha(value.tree_sha, 40, "tree_sha")
    if type(value.subject) is not str or not value.subject.strip():
        raise NativeSidecarContractError("subject must be non-empty text")
    for label in ("committed_at", "observed_at"):
        text = getattr(value, label)
        if type(text) is not str or _UTC.fullmatch(text) is None:
            raise NativeSidecarContractError(f"{label} must be canonical UTC text")
    if value.committed_at > value.observed_at:
        raise NativeSidecarContractError("commit cannot be observed before effective time")
    if type(value.production_paths) is not tuple or not value.production_paths:
        raise NativeSidecarContractError("native receipt requires production paths")
    paths = tuple(sorted(_path(path) for path in value.production_paths))
    if len(paths) != len(set(paths)):
        raise NativeSidecarContractError("production paths contain duplicates")
    for sequence, label in ((value.affected_symbols, "affected_symbols"), (value.api_delta, "api_delta")):
        if type(sequence) is not tuple or any(type(item) is not str or not item for item in sequence):
            raise NativeSidecarContractError(f"{label} requires canonical text tuple")
    if value.lifecycle_relation not in _RELATIONS:
        raise NativeSidecarContractError("lifecycle relation is outside the closed set")
    related = tuple(sorted(_sha(item, 64, "related_record_id") for item in value.related_record_ids))
    if value.lifecycle_relation != "supports" and not related:
        raise NativeSidecarContractError("non-support relation requires a related record")
    profile = _sha(value.profile_sha256, 64, "profile_sha256")
    command_identity = None
    if value.behavior_evidence is None:
        status = "ABSTAINED_NO_DIFFERENTIAL_TEST"
        verified = False
    else:
        command_identity = _validate_evidence(value.behavior_evidence)
        if not value.behavior_evidence.setup_succeeded:
            status = "ABSTAINED_SETUP_FAILURE"
            verified = False
        elif not value.behavior_evidence.parent_test_patch_applied:
            status = "ABSTAINED_PARENT_TEST_PATCH_NOT_APPLIED"
            verified = False
        elif value.behavior_evidence.current_returncode != 0:
            status = "ABSTAINED_CURRENT_TEST_FAILURE"
            verified = False
        elif value.behavior_evidence.parent_returncode == 0:
            status = "ABSTAINED_NO_PARENT_FAILURE"
            verified = False
        else:
            status = "VERIFIED_BEHAVIOR_CHANGE"
            verified = True
    evidence_fields = None
    if value.behavior_evidence is not None:
        evidence_fields = {
            "command_argv": list(value.behavior_evidence.command_argv),
            "environment_sha256": value.behavior_evidence.environment_sha256,
            "test_patch_sha256": value.behavior_evidence.test_patch_sha256,
            "changed_test_paths": list(value.behavior_evidence.changed_test_paths),
            "parent_test_patch_applied": value.behavior_evidence.parent_test_patch_applied,
            "setup_succeeded": value.behavior_evidence.setup_succeeded,
            "setup_stdout_sha256": value.behavior_evidence.setup_stdout_sha256,
            "setup_stderr_sha256": value.behavior_evidence.setup_stderr_sha256,
            "parent_returncode": value.behavior_evidence.parent_returncode,
            "parent_stdout_sha256": value.behavior_evidence.parent_stdout_sha256,
            "parent_stderr_sha256": value.behavior_evidence.parent_stderr_sha256,
            "current_returncode": value.behavior_evidence.current_returncode,
            "current_stdout_sha256": value.behavior_evidence.current_stdout_sha256,
            "current_stderr_sha256": value.behavior_evidence.current_stderr_sha256,
        }
    fields = {
        "schema_version": "cp2-137-native-sidecar-receipt-v1",
        "repository": value.repository,
        "commit_sha": commit,
        "parent_sha": parent,
        "tree_sha": tree,
        "subject": value.subject.strip(),
        "committed_at": value.committed_at,
        "observed_at": value.observed_at,
        "production_paths": list(paths),
        "affected_symbols": list(value.affected_symbols),
        "api_delta": list(value.api_delta),
        "lifecycle_relation": value.lifecycle_relation,
        "related_record_ids": list(related),
        "behavior_status": status,
        "behavior_verified": verified,
        "command_identity_sha256": command_identity,
        "behavior_evidence": evidence_fields,
        "profile_sha256": profile,
    }
    canonical = _canonical_bytes(fields)
    identity = _sha256(canonical)
    return NativeSidecarReceipt(
        schema_version=fields["schema_version"],
        repository=value.repository,
        commit_sha=commit,
        parent_sha=parent,
        tree_sha=tree,
        subject=value.subject.strip(),
        committed_at=value.committed_at,
        observed_at=value.observed_at,
        production_paths=paths,
        affected_symbols=value.affected_symbols,
        api_delta=value.api_delta,
        lifecycle_relation=value.lifecycle_relation,
        related_record_ids=related,
        behavior_status=status,
        behavior_verified=verified,
        command_identity_sha256=command_identity,
        behavior_evidence=value.behavior_evidence,
        profile_sha256=profile,
        canonical_bytes=canonical,
        canonical_sha256=identity,
        identity_sha256=identity,
    )


__all__ = [
    "NativeBehaviorEvidence",
    "NativeSidecarContractError",
    "NativeSidecarInput",
    "NativeSidecarReceipt",
    "compile_native_sidecar_receipt",
]
