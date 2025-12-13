#!/usr/bin/env python3
"""
Build ESP32C5 firmware inside the official ESP-IDF docker image.

Usage:
    python ESP32C5/tools/build_bin_docker.py [--image espressif/idf:v6.0-dev]

The script mounts the repo into the container and runs the same
container_build.sh used in CI (with --no-docker so it stays inside).
Resulting binaries land in ESP32C5/binaries-esp32c5.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        default="espressif/idf:v6.0-dev",
        help="Docker image to use (default: espressif/idf:v6.0-dev)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    workflow_script = repo_root / ".github" / "scripts" / "container_build.sh"

    if not workflow_script.is_file():
        print(f"Missing build script: {workflow_script}", file=sys.stderr)
        return 1

    # Docker wants POSIX-style paths for the mount; assume Linux host.
    mount_src = repo_root.as_posix()

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{mount_src}:/project",
        "-w",
        "/project",
        "-e",
        "IDF_PY_FLAGS=--preview",
        args.image,
        "bash",
        "-c",
        ".github/scripts/container_build.sh --no-docker",
    ]

    print("Running build inside docker:")
    print(" ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("docker not found. Please install Docker and ensure it's on PATH.", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        return exc.returncode

    binaries = repo_root / "ESP32C5" / "binaries-esp32c5"
    print(f"\nBuild finished. Binaries (bin/elf) should be in: {binaries}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
