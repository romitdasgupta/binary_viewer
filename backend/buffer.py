"""
Layer 1: Bounds-Checked Binary Buffer Cursor & Automatic StructField Emitter.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple


def format_raw_hex(data: bytes, max_bytes: int = 16) -> str:
    if len(data) <= max_bytes:
        return " ".join(f"{b:02x}" for b in data)
    prefix = " ".join(f"{b:02x}" for b in data[:max_bytes])
    return f"{prefix} ..."


def make_region(
    abs_offset: int,
    slice_offset: int,
    size: int,
    vmaddr: Optional[str] = None,
    vmsize: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "abs_offset": abs_offset,
        "slice_offset": slice_offset,
        "size": size,
        "vmaddr": vmaddr,
        "vmsize": vmsize,
    }


class BinaryBuffer:
    """
    Bounds-checked view over a binary file buffer (or slice within a Fat binary).
    Tracks both `slice_offset` (relative to slice_base) and `abs_offset` (relative to file start).
    """

    def __init__(
        self,
        data: bytes,
        slice_base: int = 0,
        slice_size: Optional[int] = None,
        little_endian: bool = True,
    ):
        self.full_data = data
        self.slice_base = slice_base
        self.slice_size = (
            slice_size if slice_size is not None else max(0, len(data) - slice_base)
        )
        self.little_endian = little_endian
        self._fields: List[Dict[str, Any]] = []

    @property
    def endian_char(self) -> str:
        return "<" if self.little_endian else ">"

    def sub_slice(
        self, slice_base: int, slice_size: int, little_endian: bool = True
    ) -> "BinaryBuffer":
        return BinaryBuffer(
            self.full_data,
            slice_base=slice_base,
            slice_size=slice_size,
            little_endian=little_endian,
        )

    def clone_with_fields(self, little_endian: Optional[bool] = None) -> "BinaryBuffer":
        le = self.little_endian if little_endian is None else little_endian
        return BinaryBuffer(
            self.full_data,
            slice_base=self.slice_base,
            slice_size=self.slice_size,
            little_endian=le,
        )

    def reset_fields(self) -> List[Dict[str, Any]]:
        old = self._fields
        self._fields = []
        return old

    def get_fields(self) -> List[Dict[str, Any]]:
        return list(self._fields)

    def read_bytes(self, slice_offset: int, size: int) -> bytes:
        abs_off = self.slice_base + slice_offset
        if abs_off < 0 or size < 0 or abs_off + size > len(self.full_data):
            end = min(len(self.full_data), max(0, abs_off + size))
            start = min(len(self.full_data), max(0, abs_off))
            chunk = self.full_data[start:end]
            return chunk.ljust(size, b"\x00")
        return self.full_data[abs_off : abs_off + size]

    def read_abs_bytes(self, abs_offset: int, size: int) -> bytes:
        if abs_offset < 0 or size < 0 or abs_offset + size > len(self.full_data):
            start = min(len(self.full_data), max(0, abs_offset))
            end = min(len(self.full_data), max(0, abs_offset + size))
            return self.full_data[start:end]
        return self.full_data[abs_offset : abs_offset + size]

    def unpack_at(self, fmt: str, slice_offset: int) -> Tuple[Any, ...]:
        full_fmt = (
            fmt if fmt[0] in ("<", ">", "!", "=") else (self.endian_char + fmt)
        )
        sz = struct.calcsize(full_fmt)
        raw = self.read_bytes(slice_offset, sz)
        return struct.unpack(full_fmt, raw)

    def u8(self, slice_offset: int) -> int:
        return self.unpack_at("B", slice_offset)[0]

    def i8(self, slice_offset: int) -> int:
        return self.unpack_at("b", slice_offset)[0]

    def u16(self, slice_offset: int, endian: Optional[str] = None) -> int:
        e = endian or self.endian_char
        return self.unpack_at(f"{e}H", slice_offset)[0]

    def u32(self, slice_offset: int, endian: Optional[str] = None) -> int:
        e = endian or self.endian_char
        return self.unpack_at(f"{e}I", slice_offset)[0]

    def i32(self, slice_offset: int, endian: Optional[str] = None) -> int:
        e = endian or self.endian_char
        return self.unpack_at(f"{e}i", slice_offset)[0]

    def u64(self, slice_offset: int, endian: Optional[str] = None) -> int:
        e = endian or self.endian_char
        return self.unpack_at(f"{e}Q", slice_offset)[0]

    def fixed_cstr(self, slice_offset: int, length: int) -> str:
        raw = self.read_bytes(slice_offset, length)
        nul = raw.find(b"\x00")
        if nul != -1:
            raw = raw[:nul]
        return raw.decode("utf-8", errors="replace")

    def cstr_at(self, slice_offset: int, max_len: int = 2048) -> Tuple[str, int]:
        """Returns (decoded_string, byte_length_including_null)."""
        abs_off = self.slice_base + slice_offset
        if abs_off < 0 or abs_off >= len(self.full_data):
            return "", 0
        end_limit = min(len(self.full_data), abs_off + max_len)
        nul_pos = self.full_data.find(b"\x00", abs_off, end_limit)
        if nul_pos == -1:
            raw = self.full_data[abs_off:end_limit]
            return raw.decode("utf-8", errors="replace"), len(raw)
        raw = self.full_data[abs_off:nul_pos]
        return raw.decode("utf-8", errors="replace"), (nul_pos - abs_off + 1)

    def read_uleb128(self, slice_offset: int) -> Tuple[int, int]:
        """Decodes unsigned LEB128 at slice_offset. Returns (value, byte_length)."""
        result = 0
        shift = 0
        count = 0
        abs_off = self.slice_base + slice_offset
        max_len = len(self.full_data)
        while abs_off + count < max_len and count < 10:
            byte = self.full_data[abs_off + count]
            result |= (byte & 0x7F) << shift
            count += 1
            shift += 7
            if (byte & 0x80) == 0:
                break
        return result, max(1, count)

    def read_sleb128(self, slice_offset: int) -> Tuple[int, int]:
        """Decodes signed LEB128 at slice_offset. Returns (value, byte_length)."""
        result = 0
        shift = 0
        count = 0
        byte = 0
        abs_off = self.slice_base + slice_offset
        max_len = len(self.full_data)
        while abs_off + count < max_len and count < 10:
            byte = self.full_data[abs_off + count]
            result |= (byte & 0x7F) << shift
            count += 1
            shift += 7
            if (byte & 0x80) == 0:
                break
        if shift < 64 and (byte & 0x40):
            result |= -(1 << shift)
        return result, max(1, count)

    def record_field(
        self,
        name: str,
        field_type: str,
        slice_offset: int,
        size: int,
        raw_value: Any,
        value_str: Optional[str] = None,
        interpreted: str = "",
        description: str = "",
        bit_flags: Optional[List[Dict[str, Any]]] = None,
        target_offset: Optional[int] = None,
        target_vmaddr: Optional[str] = None,
    ) -> Dict[str, Any]:
        abs_off = self.slice_base + slice_offset
        raw_bytes = self.read_bytes(slice_offset, size)
        raw_hex = format_raw_hex(raw_bytes)
        if value_str is None:
            if isinstance(raw_value, int):
                if size == 1:
                    value_str = f"0x{raw_value:02x}"
                elif size == 2:
                    value_str = f"0x{raw_value:04x}"
                elif size == 4:
                    value_str = f"0x{raw_value:08x}"
                elif size == 8:
                    value_str = f"0x{raw_value:016x}"
                else:
                    value_str = hex(raw_value)
            else:
                value_str = str(raw_value)

        field_obj: Dict[str, Any] = {
            "name": name,
            "type": field_type,
            "abs_offset": abs_off,
            "slice_offset": slice_offset,
            "size": size,
            "raw_hex": raw_hex,
            "raw_value": raw_value,
            "value": value_str,
            "interpreted": interpreted if interpreted else value_str,
            "description": description,
            "bit_flags": bit_flags if bit_flags is not None else [],
            "target_offset": target_offset,
            "target_vmaddr": target_vmaddr,
        }
        self._fields.append(field_obj)
        return field_obj
