"""Smoke tests for shadowmap."""
import sys, subprocess, pytest

def test_cli_help():
    r = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
    assert r.returncode == 0

def test_requires_target():
    r = subprocess.run([sys.executable, "main.py"], capture_output=True, text=True)
    assert r.returncode != 0 or "Usage" in (r.stdout + r.stderr)

def test_module_no_syntax_errors():
    r = subprocess.run([sys.executable, "-m", "py_compile", "main.py"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
