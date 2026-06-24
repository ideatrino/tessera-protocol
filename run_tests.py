#!/usr/bin/env python3
# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Minimal zero-dependency test runner.

Usage:  python run_tests.py
Discovers every `test_*` function in tests/test_*.py and runs it.
(If you have pytest installed, `pytest` works too — these files are
pytest-compatible.)
"""
from __future__ import annotations

import importlib.util
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
TESTS_DIR = os.path.join(ROOT, "tests")


def _load(path):
    name = "t_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    files = sorted(
        os.path.join(TESTS_DIR, f)
        for f in os.listdir(TESTS_DIR)
        if f.startswith("test_") and f.endswith(".py")
    )
    passed = failed = 0
    failures = []
    t0 = time.time()
    for f in files:
        mod = _load(f)
        tests = sorted(n for n in dir(mod) if n.startswith("test_"))
        for tname in tests:
            fn = getattr(mod, tname)
            label = f"{os.path.basename(f)}::{tname}"
            try:
                fn()
                passed += 1
                print(f"  PASS  {label}")
            except Exception as exc:  # noqa: BLE001
                failed += 1
                failures.append((label, traceback.format_exc()))
                print(f"  FAIL  {label}  -> {exc!r}")
    dt = time.time() - t0
    print("\n" + "=" * 60)
    print(f"  {passed} passed, {failed} failed in {dt:.2f}s")
    print("=" * 60)
    if failures:
        print("\n--- failure details ---")
        for label, tb in failures:
            print(f"\n### {label}\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
