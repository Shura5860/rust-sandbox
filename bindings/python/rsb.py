"""Zero-dependency Python ctypes binding for `rust-sandbox` (`librsb_ffi.so`)."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any, Sequence


def _find_library() -> Path:
    env_path = os.environ.get("RSB_FFI_LIB")
    if env_path:
        return Path(env_path)
    repo_root = Path(__file__).resolve().parents[2]
    for profile in ("release", "debug"):
        cand = repo_root / "target" / profile / "librsb_ffi.so"
        if cand.is_file():
            return cand
    raise FileNotFoundError(
        "librsb_ffi.so not found; run `cargo build --release -p rsb-ffi` or set RSB_FFI_LIB"
    )


class RustSandboxFFI:
    def __init__(self, lib_path: str | os.PathLike[str] | None = None) -> None:
        path = Path(lib_path) if lib_path else _find_library()
        self._lib = ctypes.CDLL(str(path))

        self._lib.rsb_version.restype = ctypes.c_char_p
        self._lib.rsb_landlock_abi.restype = ctypes.c_int32

        self._lib.rsb_exec_json.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.c_int32,
            ctypes.c_int32,
        ]
        self._lib.rsb_exec_json.restype = ctypes.c_void_p

        self._lib.rsb_string_free.argtypes = [ctypes.c_void_p]
        self._lib.rsb_string_free.restype = None

        self._lib.rsb_zygote_start_python.argtypes = [ctypes.c_int32, ctypes.c_int32]
        self._lib.rsb_zygote_start_python.restype = ctypes.c_void_p
        self._lib.rsb_zygote_exec_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64]
        self._lib.rsb_zygote_exec_json.restype = ctypes.c_void_p
        self._lib.rsb_zygote_free.argtypes = [ctypes.c_void_p]
        self._lib.rsb_zygote_free.restype = None

    def start_python_zygote(
        self, *, allow_network: bool = False, use_namespaces: bool = True
    ) -> "PythonZygote":
        handle = self._lib.rsb_zygote_start_python(
            1 if allow_network else 0,
            1 if use_namespaces else 0,
        )
        if not handle:
            raise RuntimeError("failed to start Python Zygote pool via rsb-ffi")
        return PythonZygote(self._lib, handle)

    @property
    def version(self) -> str:
        return self._lib.rsb_version().decode("utf-8")

    @property
    def landlock_abi(self) -> int:
        return int(self._lib.rsb_landlock_abi())

    def exec(
        self,
        command: Sequence[str],
        *,
        rw_dir: str | None = None,
        timeout_ms: int = 5000,
        allow_network: bool = False,
        use_namespaces: bool = True,
    ) -> dict[str, Any]:
        if not command:
            raise ValueError("command must not be empty")
        prog = command[0].encode("utf-8")
        rest = [a.encode("utf-8") for a in command[1:]]
        argv_arr = (ctypes.c_char_p * len(rest))(*rest) if rest else None
        rw_bytes = rw_dir.encode("utf-8") if rw_dir else None

        raw_ptr = self._lib.rsb_exec_json(
            prog,
            argv_arr,
            len(rest),
            rw_bytes,
            timeout_ms,
            1 if allow_network else 0,
            1 if use_namespaces else 0,
        )
        if not raw_ptr:
            raise RuntimeError("rsb_exec_json returned NULL")
        try:
            payload = ctypes.cast(raw_ptr, ctypes.c_char_p).value.decode("utf-8")
            return json.loads(payload)
        finally:
            self._lib.rsb_string_free(raw_ptr)


class PythonZygote:
    def __init__(self, lib: ctypes.CDLL, handle: int) -> None:
        self._lib = lib
        self._handle: int | None = handle

    def exec(self, code: str, *, timeout_ms: int = 5000) -> dict[str, Any]:
        if not self._handle:
            raise RuntimeError("Zygote pool already closed")
        raw_ptr = self._lib.rsb_zygote_exec_json(
            self._handle, code.encode("utf-8"), timeout_ms
        )
        if not raw_ptr:
            raise RuntimeError("rsb_zygote_exec_json returned NULL")
        try:
            payload = ctypes.cast(raw_ptr, ctypes.c_char_p).value.decode("utf-8")
            return json.loads(payload)
        finally:
            self._lib.rsb_string_free(raw_ptr)

    def close(self) -> None:
        if self._handle:
            self._lib.rsb_zygote_free(self._handle)
            self._handle = None

    def __enter__(self) -> "PythonZygote":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


if __name__ == "__main__":
    rsb = RustSandboxFFI()
    print(f"rsb-ffi v{rsb.version} (landlock_abi=v{rsb.landlock_abi})")
    res = rsb.exec(
        ["/bin/sh", "-c", "echo 'hello from Python ctypes -> librsb_ffi.so!'"],
        use_namespaces=False,
    )
    print(json.dumps(res, indent=2))
    with rsb.start_python_zygote(use_namespaces=False) as zyg:
        zres = zyg.exec("import math; print('zygote 10! =', math.factorial(10))")
        print(json.dumps(zres, indent=2))
