#!/usr/bin/env python3
"""Scan vitality native libraries for hidden key material."""
import zipfile
import struct
import re

apk_path = r"C:\Users\zyzmc\Downloads\vitality (1).apk"

with zipfile.ZipFile(apk_path, "r") as zf:
    # Analyze x86_64 libreverseai-core.so (the one that runs on emulator)
    data = bytearray(zf.read("lib/x86_64/libreverseai-core.so"))
    print(f"=== libreverseai-core.so x86_64 ({len(data)} bytes) ===")

    # 1. Find ALL printable strings >= 8 chars
    strings = []
    current = b""
    start = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if len(current) == 0:
                start = i
            current += bytes([byte])
        else:
            if len(current) >= 8:
                strings.append((start, current.decode("ascii")))
            current = b""

    print(f"\nTotal strings: {len(strings)}")

    # 2. Print ALL strings (not just interesting ones)
    print(f"\n=== ALL STRINGS ===")
    for off, s in strings:
        print(f"  {hex(off)}: {s}")

    # 3. Search for key derivation labels and their nearby data
    print(f"\n=== KEY DERIVATION LABELS ===")
    for off, s in strings:
        if any(kw in s.lower() for kw in ["d-key", "verdict", "wrap", "aead", "derive", "key/v1"]):
            print(f"  {hex(off)}: {s}")
            # Show data around this string
            ctx_start = max(0, off - 32)
            ctx_end = min(len(data), off + len(s) + 64)
            ctx = data[ctx_start:ctx_end]
            hexdump = ctx.hex()
            print(f"    Context: {hexdump[:128]}...")

    # 4. Search for the high-entropy blocks we found earlier
    print(f"\n=== HIGH-ENTROPY BLOCKS (potential encrypted keys) ===")
    for i in range(0, len(data) - 64, 4):
        block = data[i:i+64]
        unique = len(set(block))
        if unique >= 45:
            hex_str = block.hex()
            if not hex_str.startswith("00010203") and "ffffff" not in hex_str:
                print(f"  {hex(i)}: {hex_str[:64]}...")
                # Check what's before this block
                if i >= 16:
                    prefix = data[i-16:i].hex()
                    print(f"    Prefix: {prefix}")

    # 5. Search for the shared key pattern
    shared_key = b"7a4212da71a964f8"
    pos = data.find(shared_key)
    if pos != -1:
        print(f"\n[SHARED_KEY] Found at {hex(pos)}!")
    else:
        print(f"\n[SHARED_KEY] Not found in binary")

    # 6. Search for any 128-char hex strings
    print(f"\n=== 128-CHAR HEX STRINGS ===")
    for m in re.finditer(rb"[0-9a-f]{128}", data):
        s = m.group().decode()
        if not s.startswith("00010203"):
            print(f"  {hex(m.start())}: {s}")

    # 7. Search for 64-char hex strings
    print(f"\n=== 64-CHAR HEX STRINGS ===")
    for m in re.finditer(rb"[0-9a-f]{64}", data):
        s = m.group().decode()
        if not s.startswith("00010203"):
            print(f"  {hex(m.start())}: {s}")

    # 8. Look for data near "d-key/v1" label
    dkey_pos = data.find(b"d-key/v1")
    if dkey_pos != -1:
        print(f"\n=== DATA NEAR d-key/v1 ===")
        # Show 256 bytes before and after
        ctx_start = max(0, dkey_pos - 128)
        ctx_end = min(len(data), dkey_pos + 128)
        ctx = data[ctx_start:ctx_end]
        print(f"  Range: {hex(ctx_start)} to {hex(ctx_end)}")
        # Print as hex dump with ASCII
        for i in range(0, len(ctx), 16):
            chunk = ctx[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {hex(ctx_start+i)}: {hex_str:<48s} {ascii_str}")

    # 9. Look for the .rodata section specifically
    # Parse ELF to find .rodata
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * 64
        sh_name = struct.unpack_from("<I", data, off)[0]
        sh_type = struct.unpack_from("<I", data, off + 4)[0]
        sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", data, off + 32)[0]
        sections.append({"name_idx": sh_name, "type": sh_type, "offset": sh_offset, "size": sh_size})

    shstrtab = sections[e_shstrndx]
    shstrtab_data = data[shstrtab["offset"]:shstrtab["offset"] + shstrtab["size"]]

    def get_section_name(s):
        end = shstrtab_data.find(b"\x00", s["name_idx"])
        return shstrtab_data[s["name_idx"]:end].decode("ascii", errors="replace")

    print(f"\n=== SECTIONS ===")
    for s in sections:
        name = get_section_name(s)
        if s["size"] > 0:
            print(f"  {name}: offset={hex(s['offset'])} size={hex(s['size'])}")

    # Find .rodata
    rodata_sec = None
    for s in sections:
        if get_section_name(s) == ".rodata":
            rodata_sec = s
            break

    if rodata_sec:
        print(f"\n=== .rodata SECTION ({hex(rodata_sec['offset'])} to {hex(rodata_sec['offset'] + rodata_sec['size'])}) ===")
        rodata = data[rodata_sec["offset"]:rodata_sec["offset"] + rodata_sec["size"]]

        # Print ALL strings in .rodata
        print(f"\n=== ALL .rodata STRINGS ===")
        current = b""
        start = 0
        for i, byte in enumerate(rodata):
            if 32 <= byte < 127:
                if len(current) == 0:
                    start = i
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    s = current.decode("ascii")
                    print(f"  {hex(rodata_sec['offset'] + start)}: {s}")
                current = b""
