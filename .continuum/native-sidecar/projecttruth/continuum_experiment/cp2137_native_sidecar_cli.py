"""Command-line entrypoint for the vendorable Native Sidecar CI bundle."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from projecttruth.continuum_experiment.cp2137_native_sidecar_ci import (
    execute_native_sidecar_ci,
    load_native_sidecar_profile,
    prepare_native_sidecar_plan,
)


def _write_once(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise RuntimeError("output receipt already exists")
    profile = load_native_sidecar_profile(args.profile)
    observed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    plan = prepare_native_sidecar_plan(
        repository_path=args.repository.resolve(),
        profile=profile,
        commit_sha=args.commit,
        observed_at=observed_at,
    )
    work_root = args.output.parent.resolve() / f".native-sidecar-work-{plan.commit_sha[:12]}"
    receipt = execute_native_sidecar_ci(
        repository_path=args.repository.resolve(),
        profile=profile,
        plan=plan,
        work_root=work_root,
    )
    payload = {
        "receipt": json.loads(receipt.canonical_bytes),
        "identity_sha256": receipt.identity_sha256,
        "behavior_status": receipt.behavior_status,
        "behavior_verified": receipt.behavior_verified,
        "plan_identity_sha256": plan.identity_sha256,
    }
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    _write_once(args.output.resolve(), rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
