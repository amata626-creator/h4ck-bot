"""
Minimal decoder for Android binary XML (AXML) — enough to read an
AndroidManifest.xml out of an APK without any third-party dependency.

This is deliberately small and defensive: it parses the string pool and the
XML start-element chunks, resolving each element's tag name and its
attributes into a plain {name: value} dict. It does NOT aim to reproduce a
byte-perfect XML tree — just the facts the static checks need (component
declarations, flags like debuggable/exported, permissions, sdk versions).

Format reference (AOSP ResChunk_header / ResXMLTree):
  chunk types:
    0x0001 RES_STRING_POOL_TYPE
    0x0003 RES_XML_TYPE (file header)
    0x0100 RES_XML_START_NAMESPACE_TYPE
    0x0101 RES_XML_END_NAMESPACE_TYPE
    0x0102 RES_XML_START_ELEMENT_TYPE
    0x0103 RES_XML_END_ELEMENT_TYPE
    0x0180 RES_XML_RESOURCE_MAP_TYPE
  attribute typed value dataTypes:
    0x03 TYPE_STRING   (data = string-pool index)
    0x10 TYPE_INT_DEC
    0x11 TYPE_INT_HEX
    0x12 TYPE_INT_BOOLEAN (data != 0 => true)

Attribute *names* in an aapt-built manifest are present in the string pool,
so they resolve directly. When a name can't be resolved (rare), the element
simply won't carry that attribute and the dependent check abstains rather
than guessing — in line with the no-false-positives rule.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103
_RESOURCE_MAP = 0x0180
_UTF8_FLAG = 1 << 8
_NO_ENTRY = 0xFFFFFFFF

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12


class AxmlError(ValueError):
    pass


@dataclass
class AxmlElement:
    tag: str
    attrs: dict = field(default_factory=dict)   # local-name -> string value
    depth: int = 0


def _read_string_pool(data: bytes, off: int) -> list[str]:
    # ResChunk_header: type(2) headerSize(2) size(4)
    chunk_type, header_size, size = struct.unpack_from("<HHI", data, off)
    if chunk_type != _RES_STRING_POOL:
        raise AxmlError("expected string pool chunk")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, off + 8
    )
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = off + 8 + 20
    strings_base = off + strings_start
    out: list[str] = []
    for i in range(string_count):
        (str_off,) = struct.unpack_from("<I", data, offsets_base + i * 4)
        p = strings_base + str_off
        try:
            out.append(_decode_pool_string(data, p, is_utf8))
        except Exception:
            out.append("")
    return out


def _decode_pool_string(data: bytes, p: int, is_utf8: bool) -> str:
    if is_utf8:
        # UTF-8: one varint for #chars, one for #bytes, then bytes, then 0x00
        n_chars, p = _u8len(data, p)
        n_bytes, p = _u8len(data, p)
        return data[p:p + n_bytes].decode("utf-8", "replace")
    # UTF-16LE: one u16 (or extended) for length, then length*2 bytes, then 0x0000
    length, p = _u16len(data, p)
    return data[p:p + length * 2].decode("utf-16-le", "replace")


def _u8len(data: bytes, p: int):
    val = data[p]
    if val & 0x80:
        val = ((val & 0x7F) << 8) | data[p + 1]
        return val, p + 2
    return val, p + 1


def _u16len(data: bytes, p: int):
    (val,) = struct.unpack_from("<H", data, p)
    if val & 0x8000:
        (val2,) = struct.unpack_from("<H", data, p + 2)
        val = ((val & 0x7FFF) << 16) | val2
        return val, p + 4
    return val, p + 2


def _resolve(idx: int, pool: list[str]) -> str:
    if idx == _NO_ENTRY or idx >= len(pool):
        return ""
    return pool[idx]


def parse_axml(data: bytes) -> list[AxmlElement]:
    """Return the start elements of a binary AndroidManifest.xml in document
    order, each with a resolved tag name, attribute dict, and nesting depth."""
    if len(data) < 8:
        raise AxmlError("file too small to be AXML")
    magic, _hdr, _size = struct.unpack_from("<HHI", data, 0)
    if magic != _RES_XML:
        raise AxmlError("not an AXML file (bad magic)")

    # Find and read the string pool (it follows the file header).
    pool_off = 8
    pool = _read_string_pool(data, pool_off)

    elements: list[AxmlElement] = []
    depth = 0
    off = 8
    n = len(data)
    while off + 8 <= n:
        chunk_type, header_size, size = struct.unpack_from("<HHI", data, off)
        if size == 0:
            break
        if chunk_type == _START_ELEMENT:
            el = _parse_start_element(data, off, pool, depth)
            elements.append(el)
            depth += 1
        elif chunk_type == _END_ELEMENT:
            depth = max(0, depth - 1)
        # string pool / resource map / namespaces: skip by size
        off += size
    return elements


def _parse_start_element(data: bytes, off: int, pool: list[str], depth: int) -> AxmlElement:
    # header(8) lineNumber(4) comment(4) ns(4) name(4)
    # attributeStart(2) attributeSize(2) attributeCount(2) id/class/style(2 each)
    base = off + 8
    (ns_idx,) = struct.unpack_from("<I", data, base + 8)  # noqa: F841
    (name_idx,) = struct.unpack_from("<I", data, base + 12)
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, base + 16)
    tag = _resolve(name_idx, pool)
    attrs: dict = {}
    # attributeStart is relative to the attrExt struct, which begins right
    # after the 16-byte ResXMLTree_node header (off+16).
    ap = off + 16 + attr_start
    for _ in range(attr_count):
        # ns(4) name(4) rawValue(4) size(2) res0(1) dataType(1) data(4)
        a_ns, a_name, a_raw = struct.unpack_from("<III", data, ap)
        _sz, _res0, a_type = struct.unpack_from("<HBB", data, ap + 12)
        (a_data,) = struct.unpack_from("<I", data, ap + 16)
        local = _resolve(a_name, pool)
        attrs[local] = _attr_value(a_type, a_raw, a_data, pool)
        ap += 20
    return AxmlElement(tag=tag, attrs=attrs, depth=depth)


def _attr_value(a_type: int, a_raw: int, a_data: int, pool: list[str]) -> str:
    if a_raw != _NO_ENTRY:
        s = _resolve(a_raw, pool)
        if s:
            return s
    if a_type == _TYPE_STRING:
        return _resolve(a_data, pool)
    if a_type == _TYPE_INT_BOOLEAN:
        return "true" if a_data != 0 else "false"
    if a_type == _TYPE_INT_HEX:
        return hex(a_data)
    if a_type == _TYPE_INT_DEC:
        # ints are stored unsigned; present small values plainly
        return str(a_data if a_data < 0x80000000 else a_data - 0x100000000)
    return str(a_data)
