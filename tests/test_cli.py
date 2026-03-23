"""
Tests for shadowmap.
CLI structure: main.py map <DOMAIN> [--output] [--ai-analysis] [--no-http] [--workers]
"""
import sys
import os
import subprocess
import pytest


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, "main.py"] + list(args),
        capture_output=True, text=True,
        env=env or os.environ.copy()
    )


def test_root_help():
    r = run("--help")
    assert r.returncode == 0
    assert "map" in r.stdout or "usage" in r.stdout.lower()


def test_map_help():
    r = run("map", "--help")
    assert r.returncode == 0
    assert "--output" in r.stdout


def test_map_requires_domain():
    """map subcommand must fail without a domain argument."""
    r = run("map")
    assert r.returncode != 0


def test_map_output_flag_exists():
    r = run("map", "--help")
    assert "--output" in r.stdout
    assert "--workers" in r.stdout


def test_module_compiles():
    r = subprocess.run([sys.executable, "-m", "py_compile", "main.py"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_src_compiles():
    r = subprocess.run([sys.executable, "-m", "py_compile", "src/recon.py"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
