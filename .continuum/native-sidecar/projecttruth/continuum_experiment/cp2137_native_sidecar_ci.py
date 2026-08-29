"""Deterministic parent/current CI replay for Native Sidecar receipts."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from projecttruth.continuum_experiment.cp2137_actionable_history import (
    is_actionable_production_path,
)
from projecttruth.continuum_experiment.cp2137_native_sidecar import (
    NativeBehaviorEvidence,
    NativeSidecarInput,
    NativeSidecarReceipt,
    compile_native_sidecar_receipt,
)


class NativeSidecarCIError(RuntimeError):
    """Raised when a Native Sidecar CI replay cannot be reproduced."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: bytes | object) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _safe_argv(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise NativeSidecarCIError(f"{label} requires a non-empty text array")
    forbidden = (";", "&&", "||", "`", "$(", "\n", "\r")
    if any(any(token in item for token in forbidden) for item in value):
        raise NativeSidecarCIError(f"{label} contains shell syntax")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class NativeSidecarProfile:
    schema_version: str
    repository: str
    production_prefixes: tuple[str, ...]
    test_prefixes: tuple[str, ...]
    setup_argv: tuple[tuple[str, ...], ...]
    test_argv_prefix: tuple[str, ...]
    max_changed_test_files: int

    @property
    def identity_sha256(self) -> str:
        return _digest(
            {
                "schema_version": self.schema_version,
                "repository": self.repository,
                "production_prefixes": list(self.production_prefixes),
                "test_prefixes": list(self.test_prefixes),
                "setup_argv": [list(value) for value in self.setup_argv],
                "test_argv_prefix": list(self.test_argv_prefix),
                "max_changed_test_files": self.max_changed_test_files,
            }
        )


@dataclass(frozen=True, slots=True)
class NativeSidecarPlan:
    repository: str
    commit_sha: str
    parent_sha: str
    tree_sha: str
    subject: str
    committed_at: str
    observed_at: str
    production_paths: tuple[str, ...]
    changed_test_paths: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    api_delta: tuple[str, ...]
    test_patch_bytes: bytes
    profile_sha256: str
    identity_sha256: str


_PROFILE_KEYS = {
    "schema_version",
    "repository",
    "production_prefixes",
    "test_prefixes",
    "setup_argv",
    "test_argv_prefix",
    "max_changed_test_files",
}


def load_native_sidecar_profile(path: Path) -> NativeSidecarProfile:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict or set(value) != _PROFILE_KEYS:
        raise NativeSidecarCIError("profile key set drifted")
    setup = value["setup_argv"]
    if type(setup) is not list:
        raise NativeSidecarCIError("setup argv requires an array")
    setup_argv = tuple(_safe_argv(item, "setup argv") for item in setup)
    prefixes = []
    for key in ("production_prefixes", "test_prefixes"):
        raw = value[key]
        if type(raw) is not list or not raw or any(type(item) is not str or not item for item in raw):
            raise NativeSidecarCIError(f"{key} drifted")
        prefixes.append(tuple(raw))
    maximum = value["max_changed_test_files"]
    if type(maximum) is not int or not 1 <= maximum <= 32:
        raise NativeSidecarCIError("max changed test files drifted")
    return NativeSidecarProfile(
        schema_version=str(value["schema_version"]),
        repository=str(value["repository"]),
        production_prefixes=prefixes[0],
        test_prefixes=prefixes[1],
        setup_argv=setup_argv,
        test_argv_prefix=_safe_argv(value["test_argv_prefix"], "test argv prefix"),
        max_changed_test_files=maximum,
    )


def _git(repository: Path, *args: str, binary: bool = False) -> bytes | str:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
        env.pop(key, None)
    result = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        env=env,
    )
    if result.returncode != 0:
        raise NativeSidecarCIError(result.stderr.decode(errors="replace").strip() or "Git operation failed")
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def _public_api(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    values = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            values.add(f"def {node.name}{ast.unparse(node.args)}")
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            values.add(f"class {node.name}")
    return values


def _api_delta(repository: Path, parent: str, commit: str, paths: tuple[str, ...]) -> tuple[str, ...]:
    rows = []
    for path in paths:
        if not path.endswith(".py"):
            continue
        old_result = subprocess.run(
            ("git", "-C", str(repository), "show", f"{parent}:{path}"),
            capture_output=True,
            check=False,
            text=True,
        )
        new_result = subprocess.run(
            ("git", "-C", str(repository), "show", f"{commit}:{path}"),
            capture_output=True,
            check=False,
            text=True,
        )
        old = _public_api(old_result.stdout) if old_result.returncode == 0 else set()
        new = _public_api(new_result.stdout) if new_result.returncode == 0 else set()
        rows.extend(f"ADDED {value}" for value in sorted(new - old))
        rows.extend(f"REMOVED {value}" for value in sorted(old - new))
    return tuple(rows)


def prepare_native_sidecar_plan(
    *,
    repository_path: Path,
    profile: NativeSidecarProfile,
    commit_sha: str,
    observed_at: str,
) -> NativeSidecarPlan:
    commit = str(_git(repository_path, "rev-parse", commit_sha))
    parent_line = str(_git(repository_path, "show", "-s", "--format=%P", commit))
    parents = parent_line.split()
    if len(parents) != 1:
        raise NativeSidecarCIError("native V1 requires a sole-parent commit")
    parent = parents[0]
    tree = str(_git(repository_path, "rev-parse", f"{commit}^{{tree}}"))
    subject = str(_git(repository_path, "show", "-s", "--format=%s", commit))
    epoch = int(str(_git(repository_path, "show", "-s", "--format=%ct", commit)))
    committed_at = datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    changed = tuple(str(_git(repository_path, "diff", "--name-only", parent, commit)).splitlines())
    production = tuple(
        sorted(
            path
            for path in changed
            if any(path.startswith(prefix) for prefix in profile.production_prefixes)
            and is_actionable_production_path(path)
        )
    )
    if not production:
        raise NativeSidecarCIError("commit has no profiled production change")
    tests = tuple(
        sorted(
            path
            for path in changed
            if any(path.startswith(prefix) for prefix in profile.test_prefixes)
            and (
                "tests" in PurePosixPath(path).parts
                or PurePosixPath(path).name.startswith("test_")
            )
        )
    )
    if len(tests) > profile.max_changed_test_files:
        raise NativeSidecarCIError("changed test file limit exceeded")
    patch = b"" if not tests else bytes(
        _git(repository_path, "diff", "--binary", parent, commit, "--", *tests, binary=True)
    )
    api_delta = _api_delta(repository_path, parent, commit, production)
    fields = {
        "repository": profile.repository,
        "commit_sha": commit,
        "parent_sha": parent,
        "tree_sha": tree,
        "subject": subject,
        "committed_at": committed_at,
        "observed_at": observed_at,
        "production_paths": list(production),
        "changed_test_paths": list(tests),
        "api_delta": list(api_delta),
        "test_patch_sha256": _digest(patch),
        "profile_sha256": profile.identity_sha256,
    }
    return NativeSidecarPlan(
        repository=profile.repository,
        commit_sha=commit,
        parent_sha=parent,
        tree_sha=tree,
        subject=subject,
        committed_at=committed_at,
        observed_at=observed_at,
        production_paths=production,
        changed_test_paths=tests,
        affected_symbols=tuple(value.split(" ", 2)[-1] for value in api_delta),
        api_delta=api_delta,
        test_patch_bytes=patch,
        profile_sha256=profile.identity_sha256,
        identity_sha256=_digest(fields),
    )


def _clone_checkout(source: Path, target: Path, commit: str) -> None:
    result = subprocess.run(
        ("git", "clone", "--quiet", "--no-hardlinks", str(source), str(target)),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise NativeSidecarCIError("isolated clone failed")
    _git(target, "checkout", "--quiet", "--detach", commit)


def _run(argv: tuple[str, ...], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "GIT_DIR", "GIT_WORK_TREE"):
        env.pop(key, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False, timeout=900)


def execute_native_sidecar_ci(
    *,
    repository_path: Path,
    profile: NativeSidecarProfile,
    plan: NativeSidecarPlan,
    work_root: Path,
) -> NativeSidecarReceipt:
    if not plan.changed_test_paths:
        return compile_native_sidecar_receipt(
            NativeSidecarInput(
                repository=plan.repository,
                commit_sha=plan.commit_sha,
                parent_sha=plan.parent_sha,
                tree_sha=plan.tree_sha,
                subject=plan.subject,
                committed_at=plan.committed_at,
                observed_at=plan.observed_at,
                production_paths=plan.production_paths,
                affected_symbols=plan.affected_symbols,
                api_delta=plan.api_delta,
                lifecycle_relation="supports",
                related_record_ids=(),
                behavior_evidence=None,
                profile_sha256=plan.profile_sha256,
            )
        )
    work_root.mkdir(parents=True, exist_ok=False)
    parent_root = work_root / "parent"
    current_root = work_root / "current"
    _clone_checkout(repository_path, parent_root, plan.parent_sha)
    _clone_checkout(repository_path, current_root, plan.commit_sha)
    patch_file = work_root / "test.patch"
    patch_file.write_bytes(plan.test_patch_bytes)
    applied = subprocess.run(
        ("git", "-C", str(parent_root), "apply", "--whitespace=nowarn", str(patch_file)),
        capture_output=True,
        check=False,
    ).returncode == 0
    setup_ok = applied
    setup_stdout = bytearray()
    setup_stderr = bytearray()
    for root in (parent_root, current_root):
        for command in profile.setup_argv:
            setup_result = _run(command, root)
            setup_stdout.extend(setup_result.stdout)
            setup_stderr.extend(setup_result.stderr)
            if setup_result.returncode != 0:
                setup_ok = False
                print(setup_result.stderr.decode(errors="replace")[-4000:], file=sys.stderr)
    command = (*profile.test_argv_prefix, *plan.changed_test_paths)
    parent = _run(command, parent_root) if setup_ok else subprocess.CompletedProcess(command, 125, b"", b"setup failed")
    current = _run(command, current_root) if setup_ok else subprocess.CompletedProcess(command, 125, b"", b"setup failed")
    environment_sha = _digest(
        {
            "python": sys.version,
            "profile_sha256": profile.identity_sha256,
            "command_argv": list(command),
        }
    )
    evidence = NativeBehaviorEvidence(
        command_argv=command,
        environment_sha256=environment_sha,
        test_patch_sha256=_digest(plan.test_patch_bytes),
        changed_test_paths=plan.changed_test_paths,
        parent_test_patch_applied=applied,
        setup_succeeded=setup_ok,
        setup_stdout_sha256=_digest(bytes(setup_stdout)),
        setup_stderr_sha256=_digest(bytes(setup_stderr)),
        parent_returncode=parent.returncode,
        parent_stdout_sha256=_digest(parent.stdout),
        parent_stderr_sha256=_digest(parent.stderr),
        current_returncode=current.returncode,
        current_stdout_sha256=_digest(current.stdout),
        current_stderr_sha256=_digest(current.stderr),
    )
    for root in (parent_root, current_root):
        shutil.rmtree(root / ".git", ignore_errors=True)
    return compile_native_sidecar_receipt(
        NativeSidecarInput(
            repository=plan.repository,
            commit_sha=plan.commit_sha,
            parent_sha=plan.parent_sha,
            tree_sha=plan.tree_sha,
            subject=plan.subject,
            committed_at=plan.committed_at,
            observed_at=plan.observed_at,
            production_paths=plan.production_paths,
            affected_symbols=plan.affected_symbols,
            api_delta=plan.api_delta,
            lifecycle_relation="supports",
            related_record_ids=(),
            behavior_evidence=evidence,
            profile_sha256=plan.profile_sha256,
        )
    )


__all__ = [
    "NativeSidecarCIError",
    "NativeSidecarPlan",
    "NativeSidecarProfile",
    "execute_native_sidecar_ci",
    "load_native_sidecar_profile",
    "prepare_native_sidecar_plan",
]
