#!/usr/bin/env python3
"""
CI-friendly FAP builder for FlipperLight.

- Reuses the shared SDK zips downloaded into FLIPPER/sdk by default.
- Skips interactive upload in CI or when --no-upload is passed.
- Renames outputs to <appid>_v<version>_<variant>.fap.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
APP_META = ROOT / "application.fam"

VARIANTS = (
    ("momentum_dev", ("mntm-dev", "momentum dev", "momentum-dev", "momentum_dev"), ()),
    ("momentum", ("mntm", "momentum"), ("mntm-dev",)),
    ("unleashed", ("unlsh", "unlshed", "unleashed"), ()),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build FlipperLight FAP variants")
    parser.add_argument(
        "--sdk-dir",
        type=Path,
        default=ROOT.parent / "FLIPPER" / "sdk",
        help="Directory containing Momentum/Unleashed SDK zips (default: FLIPPER/sdk)",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Do not prompt or attempt upload after build",
    )
    return parser.parse_args()


def read_metadata() -> tuple[str, str]:
    text = APP_META.read_text(encoding="utf-8", errors="ignore")
    appid = re.search(r'appid="([^"]+)"', text)
    version = re.search(r'fap_version="([^"]+)"', text)
    if not appid:
        raise RuntimeError("Could not find appid in application.fam")
    if not version:
        raise RuntimeError("Could not find fap_version in application.fam")
    return appid.group(1), version.group(1)


def pick_sdk(
    sdk_dir: Path, patterns: Iterable[str], exclude: Iterable[str] = ()
) -> Optional[Path]:
    candidates = [
        path
        for path in sdk_dir.glob("*.zip")
        if any(token in path.name.lower() for token in patterns)
        and not any(token in path.name.lower() for token in exclude)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def run_cmd(cmd: list[str]) -> None:
    print(f"\n>> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def update_sdk(sdk_path: Path) -> None:
    run_cmd(["ufbt", "update", "--hw", "f7", "--url", sdk_path.resolve().as_uri()])


def build_app() -> None:
    run_cmd(["ufbt"])


def upload_app() -> None:
    run_cmd(["ufbt", "launch"])


def rename_artifact(appid: str, version: str, variant: str) -> None:
    source = DIST_DIR / f"{appid}.fap"
    target = DIST_DIR / f"{appid}_v{version}_{variant}.fap"
    if not source.exists():
        raise FileNotFoundError(f"Build output not found: {source}")
    if target.exists():
        target.unlink()
    source.replace(target)
    print(f"Renamed to {target}")


def cleanup_dist_faps() -> None:
    for fap in DIST_DIR.glob("*.fap"):
        fap.unlink(missing_ok=True)


def ensure_dependencies() -> None:
    if shutil.which("ufbt"):
        return

    print("ufbt not found. Installing via pip...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "-U", "ufbt"], cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    if not shutil.which("ufbt"):
        raise RuntimeError(
            "ufbt still not available after installation. Ensure your Python Scripts directory is in PATH."
        )


def prompt_upload_choice(built: list[tuple[str, Path]]) -> Optional[tuple[str, Path]]:
    if not built:
        return None

    print("\nWhich FlipperLight variant do you want to upload to Flipper?")
    for idx, (variant, sdk) in enumerate(built, start=1):
        print(f"  {idx}) {variant} (SDK: {sdk.name})")
    print("  n) none / skip")

    while True:
        choice = input("Select [1-9 or n]: ").strip().lower()
        if choice in ("n", "no", "none", ""):
            return None
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(built):
                return built[index - 1]
        print("Invalid choice, try again.")


def main() -> None:
    args = parse_args()
    ensure_dependencies()
    appid, version = read_metadata()
    print(f"Detected {appid} version: {version}")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_dist_faps()

    built_variants: list[tuple[str, Path]] = []

    for variant, patterns, exclude in VARIANTS:
        sdk = pick_sdk(args.sdk_dir, patterns, exclude)
        if not sdk:
            print(f"Skipping {variant}: no matching SDK zip in {args.sdk_dir}")
            continue
        print(f"\n=== {variant.upper()} ===")
        print(f"Using SDK: {sdk.name}")
        update_sdk(sdk)
        build_app()
        rename_artifact(appid, version, variant)
        built_variants.append((variant, sdk))

    if not built_variants:
        print("No variants built (missing SDK zips?).")
        return

    should_upload = not args.no_upload and not os.getenv("CI")
    if should_upload:
        selected = prompt_upload_choice(built_variants)
        if selected:
            variant, sdk = selected
            print(f"\nUploading {variant} build using SDK {sdk.name}...")
            update_sdk(sdk)
            upload_app()
    else:
        print("Upload skipped (CI or --no-upload).")

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
