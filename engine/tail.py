#!/usr/bin/env python3
import json
import os
import time
from typing import List, Optional


class JSONLinesTailer:
    def __init__(self, path: str, start: str = "end", poll: float = 0.25):
        if start not in ("beginning", "end"):
            raise ValueError(f"start must be 'beginning' or 'end', got {start!r}")
        self.path = path
        self.start = start
        self.poll_interval = poll
        self._fp: Optional[object] = None
        self._dev: Optional[int] = None
        self._ino: Optional[int] = None
        self._offset: int = 0
        self._buf: bytes = b""

    # ------------------------------------------------------------------ low level

    def _open(self, at_end: bool) -> None:
        try:
            fp = open(self.path, "rb")  # noqa: SIM115 - lifecycle managed here
        except OSError:
            self._fp = None
            return
        st = os.fstat(fp.fileno())
        self._fp, self._dev, self._ino = fp, st.st_dev, st.st_ino
        if at_end:
            fp.seek(0, os.SEEK_END)
        self._offset = fp.tell()
        self._buf = b""

    def _reopen(self, at_end: bool) -> None:
        if self._fp is not None:
            self._fp.close()
        self._fp = None
        self._open(at_end)

    def _path_identity(self) -> (Optional[tuple], int):
        try:
            st = os.stat(self.path)
            return (st.st_dev, st.st_ino), st.st_size
        except OSError:
            return None, -1

    # ------------------------------------------------------------------ public

    def poll(self) -> List[dict]:
        """Return JSON entries written to the file since the last poll."""
        entries: List[dict] = []
        if self._fp is None:
            self._open(at_end=self.start == "end")
        if self._fp is None:
            return entries

        ident, size = self._path_identity()
        if ident is None:
            self._fp.close()
            self._fp = None
            self._buf = b""
            return entries
        if ident != (self._dev, self._ino):
            self._reopen(at_end=False)   # replaced file -> read it fresh
        elif size < self._offset:
            self._fp.seek(0)             # truncated in place -> restart
            self._offset = 0
            self._buf = b""

        if self._fp is not None:
            try:
                chunk = self._fp.read(65536)
            except OSError:
                self._fp.close()
                self._fp = None
                self._buf = b""
                chunk = b""
            if chunk:
                self._buf += chunk

        # Emit complete newline-terminated JSON objects.
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if self._fp is not None:
            self._offset = self._fp.tell()
        return entries