"""Shared fixtures and helpers for the project test suite.

These tests are only used for self-checking before submission and are not part
of the deliverable. They are allowed to call mature third-party libraries
(pycryptodome) to cross-check the homemade RSA / OAEP / CCA2 code.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TASK1_PY = ROOT / "Task1" / "src" / "py"
TASK2_PY = ROOT / "Task2" / "src" / "py"
TASK3_PY = ROOT / "Task3" / "src" / "py"

TASK1_CPP = ROOT / "Task1" / "src" / "cpp"
TASK2_CPP = ROOT / "Task2" / "src" / "cpp"
TASK3_CPP = ROOT / "Task3" / "src" / "cpp"

for path in (TASK1_PY, TASK2_PY, TASK3_PY):
    sys.path.insert(0, str(path))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def rsa_core():
    return _load("rsa_core", TASK1_PY / "rsa_core.py")


@pytest.fixture(scope="session")
def oaep():
    return _load("oaep", TASK3_PY / "oaep.py")


@pytest.fixture(scope="session")
def aes_utils():
    return _load("aes_utils", TASK2_PY / "aes_utils.py")


@pytest.fixture(scope="session")
def keypair(rsa_core):
    """A single 1024-bit key pair shared by the whole session (slow to make)."""
    return rsa_core.generate_rsa_keypair(1024)


def have_cpp():
    """True when g++ and the GMP/OpenSSL headers are available."""
    return subprocess.call(["which", "g++"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0


requires_cpp = pytest.mark.skipif(not have_cpp(),
                                  reason="g++ / GMP / OpenSSL not available")


def make(directory):
    """Build the C++ programs in a task directory."""
    subprocess.run(["make"], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def run(args, cwd):
    """Run a command and return its stdout text."""
    result = subprocess.run(args, cwd=cwd, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    return result.stdout


def grep(text, prefix):
    """Return the value after the first line starting with prefix."""
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    raise AssertionError(f"prefix {prefix!r} not found in:\n{text}")
