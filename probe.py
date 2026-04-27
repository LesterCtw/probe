#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe.py - Standard-library environment probe for locked-down Windows/Python machines.

Designed for the case where you cannot bring files home:
- It prints a single all-numeric summary code.
- The code is fixed-schema and can be decoded later.
- It also writes JSON/Markdown reports locally when possible.

Default behavior:
- Uses only the Python standard library.
- Does not install anything.
- Does not contact the network unless --network is passed.
- Does not run external tool commands unless explicitly requested.
- Redacts common secrets and user/machine identifiers in text reports.

Typical usage on the company Windows 11 / Python 3.12 machine:
    python probe.py
    python probe.py --network
    python probe.py --network --run-pip-commands
    python probe.py --no-files --network

At home, decode a copied code:
    python probe.py --decode 312801...
"""

from __future__ import annotations

import argparse
import configparser
import ctypes
import datetime as _dt
import getpass
import hashlib
import importlib
import importlib.metadata as metadata
import json
import os
import platform
import re
import shutil
import signal
import site
import socket
import ssl
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import time
import traceback
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


NUMERIC_CODE_SCHEMA_ID = "312801"
NUMERIC_CHECKSUM_MOD = 97

# One digit per field after the 6-digit schema header.
# General convention: 0 = unknown/not run/error, 1 = yes/OK/available, 2 = no/fail/unavailable.
# Some fields define additional values in their legend.
NUMERIC_CODE_FIELDS: list[dict[str, str]] = [
    {"id": "network_requested", "label": "--network was used"},
    {"id": "run_tool_commands", "label": "--run-tool-commands was used"},
    {"id": "run_pip_commands", "label": "--run-pip-commands was used"},
    {"id": "os_windows", "label": "OS is Windows"},
    {"id": "windows11", "label": "Windows build looks like Windows 11"},
    {"id": "is_admin", "label": "Current process has admin rights"},
    {"id": "process_64bit", "label": "Python process is 64-bit"},
    {"id": "cpython", "label": "Python implementation is CPython"},
    {"id": "python_312", "label": "Python version is 3.12.x"},
    {"id": "python_64bit", "label": "sys.maxsize indicates 64-bit Python"},
    {"id": "virtualenv_active", "label": "A virtual environment is active"},
    {"id": "user_site_enabled", "label": "Python user-site packages are enabled"},
    {"id": "pip_import", "label": "import pip works"},
    {"id": "setuptools_import", "label": "import setuptools works"},
    {"id": "wheel_import", "label": "import wheel works"},
    {"id": "ensurepip_import", "label": "import ensurepip works"},
    {"id": "venv_import", "label": "import venv works"},
    {"id": "venv_create_without_pip", "label": "Can create a venv without pip"},
    {"id": "ssl_import", "label": "import ssl works"},
    {"id": "sqlite_import", "label": "import sqlite3 works"},
    {"id": "sqlite_runtime", "label": "SQLite in-memory smoke test works"},
    {"id": "subprocess_child", "label": "Can launch a child Python subprocess"},
    {"id": "write_cwd", "label": "Can write in current working directory"},
    {"id": "write_temp", "label": "Can write in temp directory"},
    {"id": "write_output_dir", "label": "Can write in output directory"},
    {"id": "pip_env_vars", "label": "pip/proxy/cert related environment variables exist"},
    {"id": "pip_config_readable", "label": "At least one pip config file exists and is readable"},
    {"id": "pip_index_custom", "label": "Custom pip index/index-url is configured"},
    {"id": "pip_find_links_or_no_index", "label": "pip no-index or find-links is configured"},
    {"id": "pip_require_virtualenv", "label": "pip require-virtualenv is enabled"},
    {"id": "proxy_detected", "label": "HTTP/HTTPS proxy is detected"},
    {"id": "ca_bundle_env", "label": "Custom CA bundle/cert environment variable is set"},
    {"id": "pythonpath_env", "label": "PYTHONPATH/PYTHONHOME/PYTHONUSERBASE is set"},
    {"id": "tool_git", "label": "git is on PATH"},
    {"id": "tool_docker", "label": "docker is on PATH"},
    {"id": "tool_uv", "label": "uv is on PATH"},
    {"id": "tool_conda_mamba", "label": "conda or mamba is on PATH"},
    {"id": "tool_poetry_pipx_virtualenv", "label": "poetry, pipx, or virtualenv is on PATH"},
    {"id": "tool_node_npm", "label": "node or npm is on PATH"},
    {"id": "tool_java", "label": "java or javac is on PATH"},
    {"id": "tool_dotnet", "label": "dotnet is on PATH"},
    {"id": "tool_build_chain", "label": "C/C++ or native build tools are on PATH"},
    {"id": "tool_win_pkg_mgr", "label": "winget, choco, or scoop is on PATH"},
    {"id": "tool_powershell", "label": "powershell or pwsh is on PATH"},
    {"id": "tool_curl_certutil", "label": "curl or certutil is on PATH"},
    {"id": "pypi_https_head", "label": "PyPI/files.pythonhosted HTTPS HEAD reachability", "legend": "0=not run, 1=both OK, 2=both failed, 3=partial"},
    {"id": "github_https_head", "label": "GitHub HTTPS HEAD reachability", "legend": "0=not run, 1=OK, 2=failed"},
    {"id": "pypi_direct_tls", "label": "Direct TLS to PyPI/files.pythonhosted", "legend": "0=not run, 1=both OK, 2=both failed, 3=partial"},
    {"id": "installed_package_count", "label": "Installed package count", "legend": "0=unknown, 1=0, 2=1-19, 3=20-99, 4=100-299, 5=300+"},
    {"id": "pip_list_json", "label": "pip list --format=json result", "legend": "0=not run, 1=OK, 2=command failed, 3=parse error"},
    {"id": "errors_or_timeouts", "label": "Collector errors or command timeouts", "legend": "1=none detected, 2=collector error, 3=command timeout, 4=both"},
    {"id": "long_paths_enabled", "label": "Windows LongPathsEnabled registry value", "legend": "0=unknown/not Windows, 1=enabled, 2=disabled/missing"},
    {"id": "path_length_category", "label": "PATH environment variable length", "legend": "0=unknown, 1=<=2048, 2=2049-8191, 3=>=8192"},
    {"id": "write_user_site", "label": "Can write to Python user-site directory"},
    {"id": "write_purelib", "label": "Can write to active Python site-packages/purelib directory"},
]

IMPORTANT_ENV_KEYS = [
    "PATH",
    "PATHEXT",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PIP_CONFIG_FILE",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_TRUSTED_HOST",
    "PIP_REQUIRE_VIRTUALENV",
    "PIP_NO_INDEX",
    "PIP_FIND_LINKS",
    "PIP_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "COMSPEC",
    "PSModulePath",
]

PIP_RELATED_ENV_KEYS = {
    "PIP_CONFIG_FILE",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_TRUSTED_HOST",
    "PIP_REQUIRE_VIRTUALENV",
    "PIP_NO_INDEX",
    "PIP_FIND_LINKS",
    "PIP_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
}

TOOL_NAMES = [
    "python",
    "py",
    "pip",
    "git",
    "docker",
    "uv",
    "brew",
    "conda",
    "mamba",
    "poetry",
    "pipx",
    "virtualenv",
    "node",
    "npm",
    "java",
    "javac",
    "dotnet",
    "go",
    "rustc",
    "cargo",
    "cl",
    "cmake",
    "ninja",
    "make",
    "gcc",
    "g++",
    "winget",
    "choco",
    "scoop",
    "powershell",
    "pwsh",
    "cmd",
    "where",
    "curl",
    "certutil",
]

PYTHON_IMPORT_CHECKS = [
    "pip",
    "setuptools",
    "wheel",
    "venv",
    "ensurepip",
    "ssl",
    "sqlite3",
    "tkinter",
    "ctypes",
    "multiprocessing",
    "subprocess",
    "asyncio",
    "urllib.request",
    "json",
    "zipfile",
    "tarfile",
    "bz2",
    "lzma",
    "zlib",
    "readline",
    "curses",
    "winreg",
    "msvcrt",
]

NETWORK_TARGETS = [
    "https://pypi.org/simple/pip/",
    "https://files.pythonhosted.org/",
    "https://www.python.org/",
    "https://github.com/",
]

SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|passwd|password|pwd|credential|auth|cookie|session|bearer|apikey|api_key|private|ssh|cert|key)",
    re.IGNORECASE,
)


def now_utc_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def format_groups(value: str, size: int = 4) -> str:
    return " ".join(value[i : i + size] for i in range(0, len(value), size))


def checksum_digits(payload: str) -> str:
    digest = hashlib.sha256(payload.encode("ascii", errors="ignore")).hexdigest()
    return f"{int(digest, 16) % NUMERIC_CHECKSUM_MOD:02d}"


def strip_to_digits(value: str) -> str:
    return "".join(ch for ch in str(value) if ch.isdigit())


def truthy_env_value(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    return bool(text) and text not in {"0", "false", "no", "off", "none", "null"}


def digit_bool(value: Any) -> str:
    if value is True:
        return "1"
    if value is False:
        return "2"
    return "0"


def digit_present(value: Any) -> str:
    return "1" if value else "2"


def redact_url_userinfo(value: str) -> str:
    if not value:
        return value

    pattern = re.compile(
        r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<userinfo>[^\s/@:]+(?::[^\s/@]*)?@)(?P<host>[^\s/;]+)"
    )
    return pattern.sub(lambda m: f"{m.group('scheme')}<redacted>@{m.group('host')}", value)


class Redactor:
    def __init__(self, unsafe_full: bool = False):
        self.unsafe_full = unsafe_full
        self.username = ""
        self.home = ""
        self.computername = ""
        self.fqdn = ""
        try:
            self.username = getpass.getuser() or ""
        except Exception:
            pass
        try:
            self.home = str(Path.home())
        except Exception:
            pass
        try:
            self.computername = os.environ.get("COMPUTERNAME", "") or platform.node()
        except Exception:
            pass
        try:
            self.fqdn = socket.getfqdn()
        except Exception:
            pass

    def text(self, value: Any) -> Any:
        if self.unsafe_full or value is None or not isinstance(value, str):
            return value
        out = redact_url_userinfo(value)
        replacements = []
        if self.home:
            replacements.append((self.home, "%USERPROFILE%"))
            replacements.append((self.home.replace("\\", "/"), "%USERPROFILE%"))
        if self.username:
            replacements.append((self.username, "%USERNAME%"))
        if self.computername:
            replacements.append((self.computername, "%COMPUTERNAME%"))
        if self.fqdn and self.fqdn != self.computername:
            replacements.append((self.fqdn, "%FQDN%"))
        for old, new in sorted(replacements, key=lambda pair: len(pair[0]), reverse=True):
            if old:
                out = out.replace(old, new)
        return out

    def env_value(self, key: str, value: str) -> str:
        if self.unsafe_full:
            return value
        if SENSITIVE_KEY_RE.search(key):
            return f"<redacted:{safe_hash(value)}>"
        return self.text(redact_url_userinfo(value))


def redact_obj(obj: Any, redactor: Redactor) -> Any:
    if redactor.unsafe_full:
        return obj
    if isinstance(obj, str):
        return redactor.text(obj)
    if isinstance(obj, list):
        return [redact_obj(item, redactor) for item in obj]
    if isinstance(obj, tuple):
        return [redact_obj(item, redactor) for item in obj]
    if isinstance(obj, dict):
        return {str(redact_obj(k, redactor)): redact_obj(v, redactor) for k, v in obj.items()}
    return obj


def try_call(fn, default=None):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"} if default is None else default


def run_cmd(args: list[str], timeout: float, redactor: Redactor, max_chars: int = 120_000) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "args": args,
        "found_executable": shutil.which(args[0]) if args else None,
        "ok": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "elapsed_seconds": None,
        "timed_out": False,
        "error": None,
    }
    if not args:
        result["error"] = "empty command"
        return result

    creationflags = 0
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True

    proc = None
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            creationflags=creationflags,
            **popen_kwargs,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        timeout=2,
                    )
                    proc.kill()
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        proc.kill()
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except Exception:
                stdout, stderr = "", ""
            result["error"] = f"TimeoutExpired after {timeout}s"

        stdout = stdout or ""
        stderr = stderr or ""
        if len(stdout) > max_chars:
            stdout = stdout[:max_chars] + f"\n... <truncated after {max_chars} chars>"
        if len(stderr) > max_chars:
            stderr = stderr[:max_chars] + f"\n... <truncated after {max_chars} chars>"
        result.update(
            {
                "ok": (proc.returncode == 0) and not result["timed_out"],
                "returncode": proc.returncode,
                "stdout": redactor.text(stdout),
                "stderr": redactor.text(stderr),
                "elapsed_seconds": round(time.perf_counter() - started, 3),
            }
        )
    except FileNotFoundError as exc:
        result.update({"error": f"FileNotFoundError: {exc}", "elapsed_seconds": round(time.perf_counter() - started, 3)})
    except Exception as exc:  # noqa: BLE001
        result.update({"error": f"{type(exc).__name__}: {exc}", "elapsed_seconds": round(time.perf_counter() - started, 3)})
    return result


def is_windows_admin() -> Any:
    if os.name != "nt":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def read_registry_value(root_name: str, path: str, name: str) -> Any:
    if os.name != "nt":
        return None
    try:
        import winreg  # type: ignore

        roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        with winreg.OpenKey(roots[root_name], path) as key:
            value, value_type = winreg.QueryValueEx(key, name)
            return {"value": value, "type": value_type}
    except FileNotFoundError:
        return {"missing": True}
    except PermissionError as exc:
        return {"permission_error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def parse_windows_build(version_text: str) -> int | None:
    match = re.search(r"\b10\.0\.(\d+)", version_text or "")
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    numbers = re.findall(r"\d+", version_text or "")
    if len(numbers) >= 3:
        try:
            return int(numbers[2])
        except ValueError:
            return None
    return None


def collect_platform(redactor: Redactor) -> dict[str, Any]:
    version = platform.version()
    win32_ver = platform.win32_ver()
    build = parse_windows_build(version or (win32_ver[1] if len(win32_ver) > 1 else ""))
    info = {
        "os_name": os.name,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": version,
        "windows_build": build,
        "windows11_likely": bool(platform.system() == "Windows" and build is not None and build >= 22000),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "architecture": platform.architecture(),
        "win32_ver": win32_ver,
        "win32_edition": try_call(platform.win32_edition, default=None) if hasattr(platform, "win32_edition") else None,
        "node": platform.node(),
        "fqdn": try_call(socket.getfqdn, default=None),
        "hostname": try_call(socket.gethostname, default=None),
        "is_admin": is_windows_admin(),
        "current_user": try_call(getpass.getuser, default=None),
        "current_pid": os.getpid(),
        "cwd": os.getcwd(),
        "home": str(Path.home()),
        "cpu_count": os.cpu_count(),
        "environment_is_64bit_process": sys.maxsize > 2**32,
    }
    return redact_obj(info, redactor)


def collect_sys_flags() -> dict[str, Any]:
    names = [
        "debug",
        "inspect",
        "interactive",
        "optimize",
        "dont_write_bytecode",
        "no_user_site",
        "no_site",
        "ignore_environment",
        "verbose",
        "bytes_warning",
        "quiet",
        "hash_randomization",
        "isolated",
        "dev_mode",
        "utf8_mode",
        "warn_default_encoding",
        "safe_path",
        "int_max_str_digits",
        "gil",
        "thread_inherit_context",
        "context_aware_warnings",
    ]
    out: dict[str, Any] = {}
    for name in names:
        if hasattr(sys.flags, name):
            value = getattr(sys.flags, name)
            if isinstance(value, (str, int, bool, type(None))):
                out[name] = value
    return out


def collect_python(redactor: Redactor) -> dict[str, Any]:
    ssl_info: dict[str, Any] = {}
    try:
        ssl_info = {
            "openssl_version": ssl.OPENSSL_VERSION,
            "openssl_version_info": ssl.OPENSSL_VERSION_INFO,
            "has_sni": getattr(ssl, "HAS_SNI", None),
            "default_verify_paths": ssl.get_default_verify_paths()._asdict(),
        }
    except Exception as exc:  # noqa: BLE001
        ssl_info = {"error": f"{type(exc).__name__}: {exc}"}

    sysconfig_vars = {}
    for key in [
        "ABIFLAGS",
        "EXT_SUFFIX",
        "SOABI",
        "Py_ENABLE_SHARED",
        "CC",
        "CXX",
        "LDSHARED",
        "INCLUDEPY",
        "LIBDIR",
        "LIBRARY",
        "LDLIBRARY",
        "MULTIARCH",
        "BINDIR",
        "EXE",
        "VERSION",
        "py_version",
        "py_version_short",
        "HOST_GNU_TYPE",
        "BUILD_GNU_TYPE",
    ]:
        try:
            sysconfig_vars[key] = sysconfig.get_config_var(key)
        except Exception as exc:  # noqa: BLE001
            sysconfig_vars[key] = f"ERROR: {type(exc).__name__}: {exc}"

    info = {
        "version": sys.version,
        "version_info": list(sys.version_info),
        "implementation": {
            "name": sys.implementation.name,
            "version": list(sys.implementation.version),
            "cache_tag": getattr(sys.implementation, "cache_tag", None),
        },
        "executable": sys.executable,
        "base_executable": getattr(sys, "_base_executable", None),
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "exec_prefix": sys.exec_prefix,
        "base_exec_prefix": sys.base_exec_prefix,
        "is_virtualenv": sys.prefix != sys.base_prefix,
        "real_prefix": getattr(sys, "real_prefix", None),
        "argv": sys.argv,
        "path": sys.path,
        "flags": collect_sys_flags(),
        "api_version": sys.api_version,
        "maxsize": sys.maxsize,
        "byteorder": sys.byteorder,
        "filesystem_encoding": sys.getfilesystemencoding(),
        "default_encoding": sys.getdefaultencoding(),
        "preferred_encoding": try_call(lambda: __import__("locale").getpreferredencoding(False), default=None),
        "stdlib_module_names_count": len(getattr(sys, "stdlib_module_names", [])),
        "site": {
            "ENABLE_USER_SITE": getattr(site, "ENABLE_USER_SITE", None),
            "USER_SITE": getattr(site, "USER_SITE", None),
            "USER_BASE": getattr(site, "USER_BASE", None),
            "getsitepackages": try_call(site.getsitepackages, default=[]),
            "getusersitepackages": try_call(site.getusersitepackages, default=None),
        },
        "sysconfig": {
            "platform": sysconfig.get_platform(),
            "paths": try_call(sysconfig.get_paths, default={}),
            "selected_config_vars": sysconfig_vars,
        },
        "ssl": ssl_info,
    }
    return redact_obj(info, redactor)


def collect_environment(redactor: Redactor) -> dict[str, Any]:
    env = dict(os.environ)
    selected = {}
    for key in IMPORTANT_ENV_KEYS:
        if key in env:
            selected[key] = redactor.env_value(key, env[key])
    env_all = {key: redactor.env_value(key, value) for key, value in sorted(env.items(), key=lambda kv: kv[0].upper())}
    path_value = env.get("PATH", "")
    path_entries = path_value.split(os.pathsep) if path_value else []
    return {
        "redaction": "off (--unsafe-full)" if redactor.unsafe_full else "on: user/home/host and common secrets redacted",
        "count": len(env),
        "keys": sorted(env.keys(), key=str.upper),
        "selected": selected,
        "path_length": len(path_value),
        "path_entries": [redactor.text(p) for p in path_entries],
        "all": env_all,
    }


def filesystem_write_test(directory: Path, redactor: Redactor, create_dir: bool = True) -> dict[str, Any]:
    result = {
        "path": redactor.text(str(directory)),
        "exists": directory.exists(),
        "is_dir": directory.is_dir(),
        "can_write": False,
        "created_dir": False,
        "error": None,
    }
    try:
        if create_dir and not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            result["created_dir"] = True
        fd, tmp_name = tempfile.mkstemp(prefix="probe_write_test_", suffix=".tmp", dir=str(directory))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("ok")
        Path(tmp_name).unlink(missing_ok=True)
        result["exists"] = directory.exists()
        result["is_dir"] = directory.is_dir()
        result["can_write"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def collect_filesystem(redactor: Redactor, output_dir: Path) -> dict[str, Any]:
    temp_dir = Path(tempfile.gettempdir())
    cwd = Path.cwd()
    home = Path.home()

    tests: dict[str, Any] = {
        "cwd": filesystem_write_test(cwd, redactor, create_dir=False),
        "tempdir": filesystem_write_test(temp_dir, redactor, create_dir=False),
        "output_dir": filesystem_write_test(output_dir, redactor, create_dir=True),
    }

    purelib_path = None
    try:
        purelib_value = sysconfig.get_paths().get("purelib")
        if purelib_value:
            purelib_path = Path(purelib_value)
            tests["purelib"] = filesystem_write_test(purelib_path, redactor, create_dir=False)
    except Exception as exc:  # noqa: BLE001
        tests["purelib"] = {"can_write": False, "error": f"{type(exc).__name__}: {exc}"}

    user_site_path = None
    try:
        user_site_value = getattr(site, "USER_SITE", None) or site.getusersitepackages()
        if user_site_value:
            user_site_path = Path(user_site_value)
            tests["user_site"] = filesystem_write_test(user_site_path, redactor, create_dir=True)
    except Exception as exc:  # noqa: BLE001
        tests["user_site"] = {"can_write": False, "error": f"{type(exc).__name__}: {exc}"}

    scripts_dir_candidates = []
    try:
        scripts_dir_candidates.append(Path(sysconfig.get_path("scripts")))
    except Exception:
        pass
    try:
        user_base = Path(site.USER_BASE) if getattr(site, "USER_BASE", None) else None
        if user_base:
            scripts_dir_candidates.append(user_base / "Scripts")
    except Exception:
        pass

    return {
        "cwd": redactor.text(str(cwd)),
        "home": redactor.text(str(home)),
        "tempdir": redactor.text(str(temp_dir)),
        "output_dir": redactor.text(str(output_dir)),
        "purelib": redactor.text(str(purelib_path)) if purelib_path else None,
        "user_site": redactor.text(str(user_site_path)) if user_site_path else None,
        "write_tests": tests,
        "scripts_dir_candidates": [redactor.text(str(p)) for p in scripts_dir_candidates],
        "path_length_registry_LongPathsEnabled": read_registry_value(
            "HKLM", r"SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled"
        ),
    }


def collect_import_checks(redactor: Redactor) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for mod in PYTHON_IMPORT_CHECKS:
        started = time.perf_counter()
        entry: dict[str, Any] = {"ok": False, "version": None, "file": None, "elapsed_seconds": None, "error": None}
        try:
            imported = importlib.import_module(mod)
            entry["ok"] = True
            entry["version"] = getattr(imported, "__version__", None)
            entry["file"] = getattr(imported, "__file__", None)
        except Exception as exc:  # noqa: BLE001
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            entry["elapsed_seconds"] = round(time.perf_counter() - started, 4)
        results[mod] = redact_obj(entry, redactor)
    return results


def collect_distributions(redactor: Redactor) -> dict[str, Any]:
    packages = []
    errors = []
    try:
        for dist in metadata.distributions():
            try:
                name = dist.metadata.get("Name") or dist.name or ""
                version = dist.version
                location = str(dist.locate_file(""))
                installer = ""
                try:
                    installer = dist.read_text("INSTALLER") or ""
                    installer = installer.strip()
                except Exception:
                    pass
                packages.append(
                    {
                        "name": name,
                        "version": version,
                        "location": redactor.text(location),
                        "installer": installer,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"outer {type(exc).__name__}: {exc}")
    packages.sort(key=lambda item: (str(item.get("name", "")).lower(), str(item.get("version", ""))))
    return {"count": len(packages), "packages": packages, "errors": errors}


def collect_pip_details(redactor: Redactor) -> dict[str, Any]:
    details: dict[str, Any] = {
        "import": {"ok": False, "version": None, "file": None, "error": None},
        "config_files": [],
        "pip_env_vars": {},
        "probable_cache_dirs": [],
    }

    try:
        import pip  # type: ignore

        details["import"] = {
            "ok": True,
            "version": getattr(pip, "__version__", None),
            "file": redactor.text(getattr(pip, "__file__", None)),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        details["import"] = {"ok": False, "version": None, "file": None, "error": f"{type(exc).__name__}: {exc}"}

    for key, value in sorted(os.environ.items(), key=lambda kv: kv[0].upper()):
        if key.upper().startswith("PIP_") or key.upper() in PIP_RELATED_ENV_KEYS:
            details["pip_env_vars"][key] = redactor.env_value(key, value)

    candidates: list[Path] = []
    env_config = os.environ.get("PIP_CONFIG_FILE")
    if env_config and env_config.lower() not in {"nul", "null", os.devnull.lower()}:
        candidates.append(Path(env_config))

    if os.name == "nt":
        for base in [os.environ.get("PROGRAMDATA"), os.environ.get("APPDATA"), os.environ.get("USERPROFILE")]:
            if base:
                candidates.append(Path(base) / "pip" / "pip.ini")
        if os.environ.get("VIRTUAL_ENV"):
            candidates.append(Path(os.environ["VIRTUAL_ENV"]) / "pip.ini")
        local = os.environ.get("LOCALAPPDATA")
        if local:
            details["probable_cache_dirs"].append(redactor.text(str(Path(local) / "pip" / "Cache")))
    else:
        candidates.extend(
            [
                Path("/etc/pip.conf"),
                Path("/etc/xdg/pip/pip.conf"),
                Path.home() / ".config" / "pip" / "pip.conf",
                Path.home() / ".pip" / "pip.conf",
                Path(sys.prefix) / "pip.conf",
            ]
        )
        if os.environ.get("XDG_CACHE_HOME"):
            details["probable_cache_dirs"].append(redactor.text(str(Path(os.environ["XDG_CACHE_HOME"]) / "pip")))
        else:
            details["probable_cache_dirs"].append(redactor.text(str(Path.home() / ".cache" / "pip")))

    seen = set()
    unique_candidates = []
    for candidate in candidates:
        try:
            key = str(candidate.expanduser().resolve())
        except Exception:
            key = str(candidate)
        if key not in seen:
            unique_candidates.append(candidate)
            seen.add(key)

    for path in unique_candidates:
        entry: dict[str, Any] = {
            "path": redactor.text(str(path)),
            "exists": False,
            "readable": False,
            "sections": {},
            "error": None,
        }
        try:
            expanded = path.expanduser()
            entry["exists"] = expanded.exists()
            if expanded.exists():
                parser = configparser.ConfigParser()
                try:
                    parser.read(expanded, encoding="utf-8")
                except UnicodeDecodeError:
                    parser.read(expanded, encoding="mbcs" if os.name == "nt" else "latin-1")
                entry["readable"] = True
                for section in parser.sections():
                    entry["sections"][section] = {
                        key: redactor.env_value(key, value) for key, value in parser.items(section)
                    }
        except Exception as exc:  # noqa: BLE001
            entry["error"] = f"{type(exc).__name__}: {exc}"
        details["config_files"].append(entry)

    return details


def which_all(command: str) -> list[str]:
    path = os.environ.get("PATH", "")
    pathexts = [""]
    if os.name == "nt":
        pathexts = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        pathexts = [""] + pathexts

    found: list[str] = []
    seen: set[str] = set()
    for raw_dir in path.split(os.pathsep):
        if not raw_dir:
            continue
        directory = Path(raw_dir.strip('"'))
        for ext in pathexts:
            candidate = directory / (command + ext)
            try:
                if candidate.exists() and candidate.is_file():
                    key = str(candidate.resolve()).lower()
                    if key not in seen:
                        found.append(str(candidate))
                        seen.add(key)
            except Exception:
                continue
    return found


def collect_tools(timeout: float, redactor: Redactor, run_tool_commands: bool = False, run_pip_commands: bool = False) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for name in TOOL_NAMES:
        first = shutil.which(name)
        all_paths = which_all(name)
        tools[name] = {
            "which": redactor.text(first) if first else None,
            "all_matches": [redactor.text(p) for p in all_paths],
            "count": len(all_paths),
        }

    version_commands: dict[str, list[str]] = {
        "python_version": [sys.executable, "--version"],
    }

    if run_tool_commands:
        version_commands.update(
            {
                "py_version": ["py", "--version"],
                "where_python": ["where", "python"] if os.name == "nt" else ["which", "-a", "python"],
                "where_pip": ["where", "pip"] if os.name == "nt" else ["which", "-a", "pip"],
                "git_version": ["git", "--version"],
                "docker_version": ["docker", "--version"],
                "uv_version": ["uv", "--version"],
                "conda_version": ["conda", "--version"],
                "node_version": ["node", "--version"],
                "npm_version": ["npm", "--version"],
                "java_version": ["java", "-version"],
                "dotnet_info": ["dotnet", "--info"],
                "cmake_version": ["cmake", "--version"],
                "ninja_version": ["ninja", "--version"],
                "gcc_version": ["gcc", "--version"],
                "winget_version": ["winget", "--version"],
                "choco_version": ["choco", "--version"],
                "scoop_version": ["scoop", "--version"],
                "powershell_version": [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "$PSVersionTable | ConvertTo-Json -Depth 3",
                ],
                "powershell_execution_policy": [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-ExecutionPolicy -List | ConvertTo-Json -Depth 3",
                ],
            }
        )

    if run_pip_commands:
        version_commands.update(
            {
                "python_m_pip_version": [sys.executable, "-m", "pip", "--version"],
                "python_m_pip_debug_verbose": [sys.executable, "-m", "pip", "debug", "--verbose"],
                "python_m_pip_config_list_verbose": [sys.executable, "-m", "pip", "config", "list", "-v"],
                "python_m_pip_list_json": [sys.executable, "-m", "pip", "list", "--format=json"],
                "python_m_pip_freeze": [sys.executable, "-m", "pip", "freeze"],
            }
        )

    commands = {name: run_cmd(cmd, timeout=timeout, redactor=redactor) for name, cmd in version_commands.items()}

    pip_list_parsed = None
    pip_list_raw = commands.get("python_m_pip_list_json", {}).get("stdout")
    if pip_list_raw:
        try:
            pip_list_parsed = json.loads(pip_list_raw)
        except Exception as exc:  # noqa: BLE001
            pip_list_parsed = {"parse_error": f"{type(exc).__name__}: {exc}"}

    return {
        "run_tool_commands": run_tool_commands,
        "run_pip_commands": run_pip_commands,
        "tools": tools,
        "commands": commands,
        "pip_list_parsed": pip_list_parsed,
    }


def collect_network(timeout: float, redactor: Redactor, enabled: bool) -> dict[str, Any]:
    proxies = urllib.request.getproxies()
    result: dict[str, Any] = {
        "enabled": enabled,
        "note": "External network tests are skipped unless --network is passed.",
        "urllib_proxies": {k: redactor.text(redact_url_userinfo(v)) for k, v in proxies.items()},
        "targets": [],
    }
    if not enabled:
        return result

    for url in NETWORK_TARGETS:
        target: dict[str, Any] = {"url": url, "dns": None, "https_head": None, "tls": None}
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        dns_started = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addrs = []
            for info in infos:
                sockaddr = info[4]
                if sockaddr:
                    addrs.append(sockaddr[0])
            target["dns"] = {
                "ok": True,
                "addresses": sorted(set(addrs)),
                "elapsed_seconds": round(time.perf_counter() - dns_started, 3),
            }
        except Exception as exc:  # noqa: BLE001
            target["dns"] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.perf_counter() - dns_started, 3),
            }

        tls_started = time.perf_counter()
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    target["tls"] = {
                        "ok": True,
                        "cipher": ssock.cipher(),
                        "tls_version": ssock.version(),
                        "cert_subject": cert.get("subject"),
                        "cert_issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "elapsed_seconds": round(time.perf_counter() - tls_started, 3),
                    }
        except Exception as exc:  # noqa: BLE001
            target["tls"] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.perf_counter() - tls_started, 3),
            }

        head_started = time.perf_counter()
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "python-env-probe/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit probe requested by user.
                target["https_head"] = {
                    "ok": True,
                    "status": getattr(resp, "status", None),
                    "reason": getattr(resp, "reason", None),
                    "final_url": redactor.text(resp.geturl()),
                    "headers_sample": {
                        key: value
                        for key, value in list(resp.headers.items())[:10]
                        if key.lower() not in {"set-cookie", "cookie", "authorization"}
                    },
                    "elapsed_seconds": round(time.perf_counter() - head_started, 3),
                }
        except Exception as exc:  # noqa: BLE001
            target["https_head"] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.perf_counter() - head_started, 3),
            }

        result["targets"].append(redact_obj(target, redactor))
    return result


def collect_runtime_tests(redactor: Redactor) -> dict[str, Any]:
    tests: dict[str, Any] = {}

    try:
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as f:
            f.write("hello")
            tmp_name = f.name
        with open(tmp_name, "r", encoding="utf-8") as f:
            content = f.read()
        Path(tmp_name).unlink(missing_ok=True)
        tests["tempfile_roundtrip"] = {"ok": content == "hello", "path": redactor.text(tmp_name)}
    except Exception as exc:  # noqa: BLE001
        tests["tempfile_roundtrip"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    try:
        cmd = [sys.executable, "-c", "import sys; print(sys.version.split()[0])"]
        tests["subprocess_python_child"] = run_cmd(cmd, timeout=5, redactor=redactor, max_chars=10_000)
    except Exception as exc:  # noqa: BLE001
        tests["subprocess_python_child"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    try:
        import sqlite3

        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        cur.execute("select sqlite_version()")
        version = cur.fetchone()[0]
        conn.close()
        tests["sqlite3_in_memory"] = {"ok": True, "sqlite_version": version}
    except Exception as exc:  # noqa: BLE001
        tests["sqlite3_in_memory"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    try:
        import venv

        with tempfile.TemporaryDirectory(prefix="probe_venv_test_") as d:
            builder = venv.EnvBuilder(with_pip=False, clear=True)
            builder.create(d)
            py_path = Path(d) / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
            tests["venv_create_without_pip"] = {"ok": py_path.exists(), "python_path": redactor.text(str(py_path))}
    except Exception as exc:  # noqa: BLE001
        tests["venv_create_without_pip"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    return tests


def pip_config_has_option(pip_details: dict[str, Any], option_names: set[str]) -> bool:
    wanted = {name.lower().replace("_", "-") for name in option_names}
    for cfg in pip_details.get("config_files", []):
        if not (cfg.get("exists") and cfg.get("readable")):
            continue
        sections = cfg.get("sections", {})
        if not isinstance(sections, dict):
            continue
        for values in sections.values():
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                normalized = str(key).lower().replace("_", "-")
                if normalized in wanted and truthy_env_value(value):
                    return True
    return False


def tool_digit(tools: dict[str, Any], *names: str) -> str:
    for name in names:
        if tools.get(name, {}).get("which"):
            return "1"
    return "2"


def network_targets_by_host(network: dict[str, Any], host_fragment: str) -> list[dict[str, Any]]:
    out = []
    for target in network.get("targets", []):
        if host_fragment.lower() in str(target.get("url", "")).lower():
            out.append(target)
    return out


def network_group_digit(network: dict[str, Any], host_fragments: list[str], key: str) -> str:
    if not network.get("enabled"):
        return "0"
    targets: list[dict[str, Any]] = []
    for fragment in host_fragments:
        targets.extend(network_targets_by_host(network, fragment))
    if not targets:
        return "0"
    states = [bool(t.get(key, {}).get("ok")) for t in targets]
    if all(states):
        return "1"
    if not any(states):
        return "2"
    return "3"


def package_count_digit(report: dict[str, Any]) -> str:
    pip_list = report.get("tools", {}).get("pip_list_parsed")
    if isinstance(pip_list, list):
        count = len(pip_list)
    else:
        count = report.get("distributions", {}).get("count")
    if not isinstance(count, int):
        return "0"
    if count == 0:
        return "1"
    if count < 20:
        return "2"
    if count < 100:
        return "3"
    if count < 300:
        return "4"
    return "5"


def pip_list_digit(report: dict[str, Any]) -> str:
    if not report.get("probe_args", {}).get("run_pip_commands"):
        return "0"
    parsed = report.get("tools", {}).get("pip_list_parsed")
    command = report.get("tools", {}).get("commands", {}).get("python_m_pip_list_json", {})
    if isinstance(parsed, list):
        return "1"
    if isinstance(parsed, dict) and parsed.get("parse_error"):
        return "3"
    if command and not command.get("ok"):
        return "2"
    return "0"


def errors_or_timeouts_digit(report: dict[str, Any]) -> str:
    collector_error = any(isinstance(v, dict) and v.get("collector_error") for v in report.values())
    timed_out = False
    for entry in report.get("tools", {}).get("commands", {}).values():
        if isinstance(entry, dict) and entry.get("timed_out"):
            timed_out = True
            break
    if collector_error and timed_out:
        return "4"
    if collector_error:
        return "2"
    if timed_out:
        return "3"
    return "1"


def long_paths_digit(report: dict[str, Any]) -> str:
    value = report.get("filesystem", {}).get("path_length_registry_LongPathsEnabled")
    if not isinstance(value, dict):
        return "0"
    if value.get("value") == 1:
        return "1"
    if value.get("missing") or value.get("value") == 0:
        return "2"
    return "0"


def path_length_digit(report: dict[str, Any]) -> str:
    length = report.get("environment", {}).get("path_length")
    if not isinstance(length, int):
        return "0"
    if length <= 2048:
        return "1"
    if length < 8192:
        return "2"
    return "3"


def build_numeric_summary(report: dict[str, Any]) -> dict[str, Any]:
    probe_args = report.get("probe_args", {})
    plat = report.get("platform", {})
    py = report.get("python", {})
    imports = report.get("import_checks", {})
    runtime = report.get("runtime_tests", {})
    filesystem = report.get("filesystem", {})
    write_tests = filesystem.get("write_tests", {})
    env_selected = report.get("environment", {}).get("selected", {})
    pip_details = report.get("pip_details", {})
    pip_env = pip_details.get("pip_env_vars", {})
    tools = report.get("tools", {}).get("tools", {})
    network = report.get("network", {})

    version_info = py.get("version_info")
    is_312 = isinstance(version_info, list) and len(version_info) >= 2 and version_info[0] == 3 and version_info[1] == 12

    pip_index_custom = any(
        truthy_env_value(pip_env.get(k)) for k in ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"]
    ) or pip_config_has_option(pip_details, {"index-url", "extra-index-url"})

    pip_find_links_or_no_index = any(
        truthy_env_value(pip_env.get(k)) for k in ["PIP_NO_INDEX", "PIP_FIND_LINKS"]
    ) or pip_config_has_option(pip_details, {"no-index", "find-links"})

    pip_require_virtualenv = truthy_env_value(pip_env.get("PIP_REQUIRE_VIRTUALENV")) or pip_config_has_option(
        pip_details, {"require-virtualenv"}
    )

    proxy_detected = bool(network.get("urllib_proxies")) or any(
        truthy_env_value(pip_env.get(k)) for k in ["HTTP_PROXY", "HTTPS_PROXY", "PIP_PROXY"]
    )

    ca_bundle_env = any(
        truthy_env_value(pip_env.get(k)) for k in ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"]
    )

    pythonpath_env = any(
        truthy_env_value(env_selected.get(k)) for k in ["PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE"]
    )

    values: dict[str, str] = {
        "network_requested": digit_bool(bool(probe_args.get("network"))),
        "run_tool_commands": digit_bool(bool(probe_args.get("run_tool_commands"))),
        "run_pip_commands": digit_bool(bool(probe_args.get("run_pip_commands"))),
        "os_windows": digit_bool(plat.get("system") == "Windows"),
        "windows11": digit_bool(plat.get("windows11_likely")),
        "is_admin": digit_bool(plat.get("is_admin") if isinstance(plat.get("is_admin"), bool) else None),
        "process_64bit": digit_bool(plat.get("environment_is_64bit_process") if isinstance(plat.get("environment_is_64bit_process"), bool) else None),
        "cpython": digit_bool(py.get("implementation", {}).get("name") == "cpython"),
        "python_312": digit_bool(is_312),
        "python_64bit": digit_bool((py.get("maxsize") or 0) > 2**32 if isinstance(py.get("maxsize"), int) else None),
        "virtualenv_active": digit_bool(py.get("is_virtualenv") if isinstance(py.get("is_virtualenv"), bool) else None),
        "user_site_enabled": digit_bool(py.get("site", {}).get("ENABLE_USER_SITE") if isinstance(py.get("site", {}).get("ENABLE_USER_SITE"), bool) else None),
        "pip_import": digit_bool(imports.get("pip", {}).get("ok")),
        "setuptools_import": digit_bool(imports.get("setuptools", {}).get("ok")),
        "wheel_import": digit_bool(imports.get("wheel", {}).get("ok")),
        "ensurepip_import": digit_bool(imports.get("ensurepip", {}).get("ok")),
        "venv_import": digit_bool(imports.get("venv", {}).get("ok")),
        "venv_create_without_pip": digit_bool(runtime.get("venv_create_without_pip", {}).get("ok")),
        "ssl_import": digit_bool(imports.get("ssl", {}).get("ok")),
        "sqlite_import": digit_bool(imports.get("sqlite3", {}).get("ok")),
        "sqlite_runtime": digit_bool(runtime.get("sqlite3_in_memory", {}).get("ok")),
        "subprocess_child": digit_bool(runtime.get("subprocess_python_child", {}).get("ok")),
        "write_cwd": digit_bool(write_tests.get("cwd", {}).get("can_write")),
        "write_temp": digit_bool(write_tests.get("tempdir", {}).get("can_write")),
        "write_output_dir": digit_bool(write_tests.get("output_dir", {}).get("can_write")),
        "pip_env_vars": digit_present(pip_env),
        "pip_config_readable": digit_bool(any(c.get("exists") and c.get("readable") for c in pip_details.get("config_files", []))),
        "pip_index_custom": digit_bool(pip_index_custom),
        "pip_find_links_or_no_index": digit_bool(pip_find_links_or_no_index),
        "pip_require_virtualenv": digit_bool(pip_require_virtualenv),
        "proxy_detected": digit_bool(proxy_detected),
        "ca_bundle_env": digit_bool(ca_bundle_env),
        "pythonpath_env": digit_bool(pythonpath_env),
        "tool_git": tool_digit(tools, "git"),
        "tool_docker": tool_digit(tools, "docker"),
        "tool_uv": tool_digit(tools, "uv"),
        "tool_conda_mamba": tool_digit(tools, "conda", "mamba"),
        "tool_poetry_pipx_virtualenv": tool_digit(tools, "poetry", "pipx", "virtualenv"),
        "tool_node_npm": tool_digit(tools, "node", "npm"),
        "tool_java": tool_digit(tools, "java", "javac"),
        "tool_dotnet": tool_digit(tools, "dotnet"),
        "tool_build_chain": tool_digit(tools, "cl", "gcc", "g++", "cmake", "ninja", "make"),
        "tool_win_pkg_mgr": tool_digit(tools, "winget", "choco", "scoop"),
        "tool_powershell": tool_digit(tools, "powershell", "pwsh"),
        "tool_curl_certutil": tool_digit(tools, "curl", "certutil"),
        "pypi_https_head": network_group_digit(network, ["pypi.org", "files.pythonhosted.org"], "https_head"),
        "github_https_head": network_group_digit(network, ["github.com"], "https_head"),
        "pypi_direct_tls": network_group_digit(network, ["pypi.org", "files.pythonhosted.org"], "tls"),
        "installed_package_count": package_count_digit(report),
        "pip_list_json": pip_list_digit(report),
        "errors_or_timeouts": errors_or_timeouts_digit(report),
        "long_paths_enabled": long_paths_digit(report),
        "path_length_category": path_length_digit(report),
        "write_user_site": digit_bool(write_tests.get("user_site", {}).get("can_write")),
        "write_purelib": digit_bool(write_tests.get("purelib", {}).get("can_write")),
    }

    digits = "".join(values.get(field["id"], "0") for field in NUMERIC_CODE_FIELDS)
    payload = NUMERIC_CODE_SCHEMA_ID + digits
    checksum = checksum_digits(payload)
    code = payload + checksum
    rows = []
    for index, field in enumerate(NUMERIC_CODE_FIELDS, start=1):
        rows.append(
            {
                "position": index,
                "absolute_digit_index": len(NUMERIC_CODE_SCHEMA_ID) + index,
                "digit": values.get(field["id"], "0"),
                "id": field["id"],
                "label": field["label"],
                "legend": field.get("legend", "0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable"),
            }
        )

    return {
        "schema_id": NUMERIC_CODE_SCHEMA_ID,
        "field_count": len(NUMERIC_CODE_FIELDS),
        "checksum_mod": NUMERIC_CHECKSUM_MOD,
        "checksum": checksum,
        "code": code,
        "grouped_code": format_groups(code),
        "general_legend": "After the 6-digit schema header: 0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable unless the field legend says otherwise. The final 2 digits are a checksum.",
        "fields": rows,
    }


def decode_numeric_code(raw_code: str) -> dict[str, Any]:
    code = strip_to_digits(raw_code)
    expected_length = len(NUMERIC_CODE_SCHEMA_ID) + len(NUMERIC_CODE_FIELDS) + 2
    result: dict[str, Any] = {
        "input_digits": code,
        "expected_length": expected_length,
        "actual_length": len(code),
        "schema_id_expected": NUMERIC_CODE_SCHEMA_ID,
        "schema_ok": False,
        "length_ok": len(code) == expected_length,
        "checksum_ok": False,
        "checksum_expected": None,
        "checksum_actual": None,
        "fields": [],
    }
    if len(code) < len(NUMERIC_CODE_SCHEMA_ID):
        return result

    schema = code[: len(NUMERIC_CODE_SCHEMA_ID)]
    result["schema_id_actual"] = schema
    result["schema_ok"] = schema == NUMERIC_CODE_SCHEMA_ID
    if len(code) >= len(NUMERIC_CODE_SCHEMA_ID) + 2:
        payload = code[:-2]
        checksum = code[-2:]
        expected = checksum_digits(payload)
        result["checksum_actual"] = checksum
        result["checksum_expected"] = expected
        result["checksum_ok"] = checksum == expected

    field_digits = code[len(NUMERIC_CODE_SCHEMA_ID) : len(NUMERIC_CODE_SCHEMA_ID) + len(NUMERIC_CODE_FIELDS)]
    for index, field in enumerate(NUMERIC_CODE_FIELDS, start=1):
        digit = field_digits[index - 1] if index - 1 < len(field_digits) else "?"
        result["fields"].append(
            {
                "position": index,
                "digit": digit,
                "id": field["id"],
                "label": field["label"],
                "legend": field.get("legend", "0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable"),
                "meaning": meaning_for_digit(field, digit),
            }
        )
    return result


def meaning_for_digit(field: dict[str, str], digit: str) -> str:
    legend = field.get("legend", "0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable")
    # For specialized legends, preserve the digit and legend rather than trying to parse every phrase.
    if "0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable" not in legend:
        return legend
    return {
        "0": "unknown / not run / error",
        "1": "yes / OK / available",
        "2": "no / fail / unavailable",
    }.get(digit, "unexpected digit")


def summarize_findings(report: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    py = report.get("python", {})
    platform_info = report.get("platform", {})
    tools = report.get("tools", {}).get("tools", {})
    imports = report.get("import_checks", {})
    network = report.get("network", {})

    findings.append(
        f"Python version_info={py.get('version_info')} executable={py.get('executable')} virtualenv={py.get('is_virtualenv')}"
    )
    findings.append(
        f"OS={platform_info.get('platform')} win11_likely={platform_info.get('windows11_likely')} admin={platform_info.get('is_admin')} 64bit_process={platform_info.get('environment_is_64bit_process')}"
    )

    missing_core = []
    for name in ["pip", "setuptools", "wheel", "venv", "ssl", "sqlite3"]:
        if not imports.get(name, {}).get("ok"):
            missing_core.append(name)
    if missing_core:
        findings.append("Missing/problem imports: " + ", ".join(missing_core))
    else:
        findings.append("Core imports passed: pip/setuptools/wheel/venv/ssl/sqlite3")

    available_tools = [
        name
        for name in ["docker", "uv", "git", "cl", "cmake", "winget", "choco", "node", "java", "dotnet"]
        if tools.get(name, {}).get("which")
    ]
    findings.append("Available notable tools: " + (", ".join(available_tools) if available_tools else "none detected"))

    pip_details = report.get("pip_details", {})
    pip_import = pip_details.get("import", {})
    if pip_import.get("ok"):
        findings.append(f"pip import: version={pip_import.get('version')} file={pip_import.get('file')}")
    else:
        findings.append(f"pip import problem: {pip_import.get('error')}")
    readable_configs = [c.get("path") for c in pip_details.get("config_files", []) if c.get("exists") and c.get("readable")]
    findings.append("Readable pip config files: " + (", ".join(readable_configs) if readable_configs else "none detected"))

    if network.get("enabled"):
        ok_heads = [t.get("url") for t in network.get("targets", []) if t.get("https_head", {}).get("ok")]
        findings.append("Network HEAD successes: " + (", ".join(ok_heads) if ok_heads else "none"))
    else:
        findings.append("Network tests skipped; rerun with --network to test PyPI/GitHub reachability")

    numeric = report.get("numeric_summary", {})
    if numeric.get("code"):
        findings.append(f"Numeric summary code: {numeric.get('code')}")

    return findings


def make_markdown(report: dict[str, Any]) -> str:
    def yn(value: Any) -> str:
        return "yes" if value else "no"

    lines: list[str] = []
    lines.append("# Python Environment Probe Report")
    lines.append("")
    lines.append(f"Generated: `{report.get('generated_at_utc')}`")
    lines.append(f"Redaction: `{report.get('redaction')}`")
    lines.append("")

    numeric = report.get("numeric_summary", {})
    if numeric:
        lines.append("## Numeric Summary Code")
        lines.append("")
        lines.append("Copy this code if files cannot leave the office:")
        lines.append("")
        lines.append("```text")
        lines.append(str(numeric.get("code", "")))
        lines.append("```")
        lines.append("")
        lines.append(f"Grouped: `{numeric.get('grouped_code')}`")
        lines.append("")
        lines.append(f"Legend: {numeric.get('general_legend')}")
        lines.append("")
        lines.append("| Pos | Digit | Field | Meaning |")
        lines.append("|---:|---:|---|---|")
        for row in numeric.get("fields", []):
            lines.append(f"| {row.get('position')} | `{row.get('digit')}` | `{row.get('id')}` | {row.get('label')} |")
        lines.append("")

    lines.append("## Summary")
    for item in report.get("summary", []):
        lines.append(f"- {item}")
    lines.append("")

    py = report.get("python", {})
    plat = report.get("platform", {})
    lines.append("## Platform")
    rows = [
        ("OS", plat.get("platform")),
        ("Windows build", plat.get("windows_build")),
        ("Windows 11 likely", plat.get("windows11_likely")),
        ("Machine", plat.get("machine")),
        ("Processor", plat.get("processor")),
        ("Admin", plat.get("is_admin")),
        ("User", plat.get("current_user")),
        ("CWD", plat.get("cwd")),
        ("Home", plat.get("home")),
    ]
    for key, value in rows:
        lines.append(f"- **{key}:** `{value}`")
    lines.append("")

    lines.append("## Python")
    rows = [
        ("Version", py.get("version")),
        ("Executable", py.get("executable")),
        ("Prefix", py.get("prefix")),
        ("Base prefix", py.get("base_prefix")),
        ("Virtualenv", py.get("is_virtualenv")),
        ("sysconfig platform", py.get("sysconfig", {}).get("platform")),
        ("OpenSSL", py.get("ssl", {}).get("openssl_version")),
        ("User site enabled", py.get("site", {}).get("ENABLE_USER_SITE")),
        ("User site", py.get("site", {}).get("USER_SITE")),
    ]
    for key, value in rows:
        lines.append(f"- **{key}:** `{value}`")
    lines.append("")

    lines.append("## Tool Availability")
    lines.append("| Tool | Found | Path |")
    lines.append("|---|---:|---|")
    for name, entry in sorted(report.get("tools", {}).get("tools", {}).items()):
        lines.append(f"| `{name}` | {yn(entry.get('which'))} | `{entry.get('which') or ''}` |")
    lines.append("")

    lines.append("## Import Checks")
    lines.append("| Module | OK | Version | File/Error |")
    lines.append("|---|---:|---|---|")
    for name, entry in sorted(report.get("import_checks", {}).items()):
        detail = entry.get("file") if entry.get("ok") else entry.get("error")
        lines.append(f"| `{name}` | {yn(entry.get('ok'))} | `{entry.get('version') or ''}` | `{detail or ''}` |")
    lines.append("")

    package_rows = report.get("distributions", {}).get("packages", [])
    if isinstance(package_rows, list):
        lines.append("## Installed Packages from importlib.metadata")
        lines.append(f"Count: **{len(package_rows)}**")
        lines.append("")
        lines.append("| Package | Version |")
        lines.append("|---|---|")
        for item in package_rows:
            lines.append(f"| `{item.get('name')}` | `{item.get('version')}` |")
        lines.append("")

    lines.append("## pip Details")
    pip_details = report.get("pip_details", {})
    pip_import = pip_details.get("import", {})
    lines.append(f"- **pip import OK:** `{pip_import.get('ok')}`")
    lines.append(f"- **pip version:** `{pip_import.get('version')}`")
    lines.append(f"- **pip file:** `{pip_import.get('file')}`")
    lines.append("### pip-related env vars")
    pip_env = pip_details.get("pip_env_vars", {})
    if pip_env:
        for key, value in sorted(pip_env.items(), key=lambda kv: kv[0].upper()):
            lines.append(f"- **{key}:** `{value}`")
    else:
        lines.append("- none detected")
    lines.append("### pip config files")
    lines.append("| Path | Exists | Readable | Sections | Error |")
    lines.append("|---|---:|---:|---|---|")
    for cfg in pip_details.get("config_files", []):
        lines.append(
            f"| `{cfg.get('path')}` | {yn(cfg.get('exists'))} | {yn(cfg.get('readable'))} | `{', '.join(cfg.get('sections', {}).keys())}` | `{cfg.get('error') or ''}` |"
        )
    lines.append("")

    lines.append("## Filesystem Write Tests")
    lines.append("| Location | Exists | Is dir | Can write | Error |")
    lines.append("|---|---:|---:|---:|---|")
    for name, entry in report.get("filesystem", {}).get("write_tests", {}).items():
        lines.append(
            f"| `{name}` | {yn(entry.get('exists'))} | {yn(entry.get('is_dir'))} | {yn(entry.get('can_write'))} | `{entry.get('error') or ''}` |"
        )
    lines.append("")

    lines.append("## Selected Environment Variables")
    selected_env = report.get("environment", {}).get("selected", {})
    if selected_env:
        for key, value in sorted(selected_env.items(), key=lambda kv: kv[0].upper()):
            if key.upper() == "PATH":
                lines.append(f"- **{key}:** see PATH entries below")
            else:
                lines.append(f"- **{key}:** `{value}`")
    else:
        lines.append("No selected env vars found.")
    lines.append("")

    lines.append("## PATH Entries")
    lines.append(f"PATH length: `{report.get('environment', {}).get('path_length')}`")
    for p in report.get("environment", {}).get("path_entries", []):
        lines.append(f"- `{p}`")
    lines.append("")

    network = report.get("network", {})
    lines.append("## Network")
    lines.append(f"Enabled: `{network.get('enabled')}`")
    proxies = network.get("urllib_proxies", {})
    lines.append("### urllib proxies")
    if proxies:
        for key, value in proxies.items():
            lines.append(f"- **{key}:** `{value}`")
    else:
        lines.append("- none detected")
    if network.get("enabled"):
        lines.append("")
        lines.append("### Network Targets")
        lines.append("| URL | DNS | Direct TLS | urllib HEAD |")
        lines.append("|---|---:|---:|---:|")
        for target in network.get("targets", []):
            lines.append(
                f"| `{target.get('url')}` | {yn(target.get('dns', {}).get('ok'))} | {yn(target.get('tls', {}).get('ok'))} | {yn(target.get('https_head', {}).get('ok'))} |"
            )
    lines.append("")

    lines.append("## Command Outputs")
    command_outputs = report.get("tools", {}).get("commands", {})
    if not command_outputs:
        lines.append("No external command outputs collected.")
        lines.append("")
    for name, entry in command_outputs.items():
        lines.append(f"### {name}")
        lines.append(f"Command: `{' '.join(entry.get('args', []))}`")
        lines.append(
            f"Return code: `{entry.get('returncode')}`; OK: `{entry.get('ok')}`; Timed out: `{entry.get('timed_out')}`; Elapsed: `{entry.get('elapsed_seconds')}`"
        )
        if entry.get("error"):
            lines.append(f"Error: `{entry.get('error')}`")
        stdout = str(entry.get("stdout") or "").strip()
        stderr = str(entry.get("stderr") or "").strip()
        if stdout:
            lines.append("stdout:")
            lines.append("```text")
            lines.append(stdout[:20_000] + ("\n... <markdown truncated>" if len(stdout) > 20_000 else ""))
            lines.append("```")
        if stderr:
            lines.append("stderr:")
            lines.append("```text")
            lines.append(stderr[:20_000] + ("\n... <markdown truncated>" if len(stderr) > 20_000 else ""))
            lines.append("```")
        lines.append("")

    lines.append("## Notes")
    lines.append("- The numeric code is designed for copying by hand; it contains no secrets.")
    lines.append("- JSON report contains the full structured data; Markdown is a readable companion.")
    lines.append("- Default output redacts common secrets and identifiers. For raw details, use --unsafe-full only if policy allows it.")
    lines.append("- Use --network to test PyPI/GitHub reachability and TLS/proxy behavior.")
    lines.append("")
    return "\n".join(lines)


def collect_report(args: argparse.Namespace) -> dict[str, Any]:
    redactor = Redactor(unsafe_full=args.unsafe_full)
    output_dir = Path(args.output_dir).expanduser().resolve()
    report: dict[str, Any] = {
        "schema_version": "2.0",
        "generated_at_utc": now_utc_iso(),
        "redaction": "off (--unsafe-full)" if args.unsafe_full else "on",
        "probe_args": {
            "network": bool(args.network),
            "timeout": args.timeout,
            "output_dir": redactor.text(str(output_dir)),
            "unsafe_full": bool(args.unsafe_full),
            "run_tool_commands": bool(args.run_tool_commands),
            "run_pip_commands": bool(args.run_pip_commands),
            "no_files": bool(args.no_files),
        },
    }

    collectors = [
        ("platform", lambda: collect_platform(redactor)),
        ("python", lambda: collect_python(redactor)),
        ("environment", lambda: collect_environment(redactor)),
        ("filesystem", lambda: collect_filesystem(redactor, output_dir)),
        ("import_checks", lambda: collect_import_checks(redactor)),
        ("distributions", lambda: collect_distributions(redactor)),
        ("pip_details", lambda: collect_pip_details(redactor)),
        ("runtime_tests", lambda: collect_runtime_tests(redactor)),
        ("tools", lambda: collect_tools(args.timeout, redactor, run_tool_commands=args.run_tool_commands, run_pip_commands=args.run_pip_commands)),
        ("network", lambda: collect_network(args.timeout, redactor, enabled=args.network)),
    ]
    for name, collector in collectors:
        try:
            report[name] = collector()
        except Exception as exc:  # noqa: BLE001
            report[name] = {
                "collector_error": f"{type(exc).__name__}: {exc}",
                "traceback": redactor.text(traceback.format_exc()),
            }

    report["numeric_summary"] = build_numeric_summary(report)
    report["summary"] = summarize_findings(report)
    return report


def write_reports(report: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"probe_{stamp}.json"
    md_path = output_dir / f"probe_{stamp}.md"
    latest_json = output_dir / "probe_latest.json"
    latest_md = output_dir / "probe_latest.md"

    json_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    md_text = make_markdown(report)
    json_path.write_text(json_text, encoding="utf-8")
    md_path.write_text(md_text, encoding="utf-8")
    latest_json.write_text(json_text, encoding="utf-8")
    latest_md.write_text(md_text, encoding="utf-8")
    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "latest_json": str(latest_json),
        "latest_markdown": str(latest_md),
    }


def print_numeric_summary(numeric: dict[str, Any]) -> None:
    print("\n[probe] COPY THIS NUMERIC CODE:")
    print(numeric.get("code", ""))
    print("\n[probe] Same code grouped for readability:")
    print(numeric.get("grouped_code", ""))
    print(
        "\n[probe] Code structure: "
        f"{len(NUMERIC_CODE_SCHEMA_ID)}-digit schema header + "
        f"{len(NUMERIC_CODE_FIELDS)} result digits + 2 checksum digits."
    )
    print("[probe] General legend: 0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable.")
    print("[probe] Field positions start immediately after the 6-digit schema header.")
    print("\n[probe] Field map:")
    for row in numeric.get("fields", []):
        legend = row.get("legend") or "0=unknown/not run/error, 1=yes/OK/available, 2=no/fail/unavailable"
        print(f"  {row.get('position'):>2}. {row.get('id'):<32} = {row.get('digit')}    {legend}")


def print_decode_result(decoded: dict[str, Any]) -> None:
    print("[probe] Numeric code decode")
    print(f"  digits:          {decoded.get('input_digits')}")
    print(f"  length:          {decoded.get('actual_length')} / expected {decoded.get('expected_length')}")
    print(f"  schema:          {decoded.get('schema_id_actual')} / expected {decoded.get('schema_id_expected')}")
    print(f"  schema_ok:       {decoded.get('schema_ok')}")
    print(f"  checksum:        {decoded.get('checksum_actual')} / expected {decoded.get('checksum_expected')}")
    print(f"  checksum_ok:     {decoded.get('checksum_ok')}")
    print("\nFields:")
    for row in decoded.get("fields", []):
        print(f"  {row.get('position'):>2}. {row.get('id'):<32} = {row.get('digit')}    {row.get('meaning')}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Probe a constrained Windows/Python environment and print a copyable numeric summary code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python probe.py
              python probe.py --network
              python probe.py --no-files --network
              python probe.py --run-tool-commands --timeout 15
              python probe.py --run-pip-commands --timeout 15
              python probe.py --decode 312801...

            Safety:
              By default, common secrets and user/machine identifiers are redacted in JSON/Markdown.
              The numeric code contains only fixed check results and no secrets.
              --unsafe-full disables redaction and should only be used if company policy permits export.
            """
        ),
    )
    parser.add_argument("--output-dir", default="probe_results", help="Directory for JSON/Markdown reports. Default: ./probe_results")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-command/network timeout in seconds. Default: 8")
    parser.add_argument("--network", action="store_true", help="Run external DNS/TLS/HTTPS tests against PyPI/Python/GitHub.")
    parser.add_argument("--no-files", action="store_true", help="Do not write JSON/Markdown files; only print console output.")
    parser.add_argument("--numeric-only", action="store_true", help="Print only the compact numeric code after collecting data.")
    parser.add_argument("--decode", help="Decode a numeric code and exit. Spaces/dashes are ignored.")
    parser.add_argument(
        "--unsafe-full",
        action="store_true",
        help="Disable redaction of env values, user names, host names, and paths. Use only if policy allows.",
    )
    parser.add_argument(
        "--run-tool-commands",
        action="store_true",
        help="Run external tool version commands such as git --version, java -version, winget --version. Default only scans PATH.",
    )
    parser.add_argument(
        "--run-pip-commands",
        action="store_true",
        help="Also run pip debug/list/config/freeze subcommands. More complete, but can be slow in locked-down environments.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        # Helps Windows terminals with non-ASCII paths while still replacing unsupported chars.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.decode:
        decoded = decode_numeric_code(args.decode)
        print_decode_result(decoded)
        return 0 if decoded.get("length_ok") and decoded.get("schema_ok") and decoded.get("checksum_ok") else 1

    output_dir = Path(args.output_dir).expanduser().resolve()

    if not args.numeric_only:
        print("[probe] Collecting environment information...")
        if not args.network:
            print("[probe] Network tests are skipped. Add --network if you need PyPI/GitHub reachability checks.")
        if not args.unsafe_full:
            print("[probe] Redaction is ON for local JSON/Markdown. The numeric code contains no secrets.")
        if not args.run_tool_commands:
            print("[probe] External tool version commands are skipped. Add --run-tool-commands if you need command outputs.")
        if not args.run_pip_commands:
            print("[probe] Slow pip subcommands are skipped. Add --run-pip-commands if you need pip debug/list/config/freeze output.")

    try:
        report = collect_report(args)
    except Exception as exc:  # noqa: BLE001
        print(f"[probe] Fatal collection error: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 2

    numeric = report.get("numeric_summary", {})

    paths = None
    write_error = None
    if not args.no_files:
        try:
            paths = write_reports(report, output_dir)
        except Exception as exc:  # noqa: BLE001
            write_error = f"{type(exc).__name__}: {exc}"

    if args.numeric_only:
        print(numeric.get("code", ""))
        return 0

    print("\n[probe] Done.")
    if paths:
        print(f"[probe] JSON report:      {paths['json']}")
        print(f"[probe] Markdown report:  {paths['markdown']}")
        print(f"[probe] Latest JSON:      {paths['latest_json']}")
        print(f"[probe] Latest Markdown:  {paths['latest_markdown']}")
    elif args.no_files:
        print("[probe] File output skipped because --no-files was used.")
    else:
        print(f"[probe] Could not write JSON/Markdown reports: {write_error}")
        print("[probe] Numeric code is still available below.")

    print_numeric_summary(numeric)

    print("\n[probe] Summary:")
    for item in report.get("summary", []):
        if str(item).startswith("Numeric summary code:"):
            continue
        print(f"  - {item}")

    print("\n[probe] If files cannot leave the office, bring back only the numeric code above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
