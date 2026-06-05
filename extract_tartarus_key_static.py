#!/usr/bin/env python3
"""
Extract tartarus API key by disassembling libtartarus_core.so ARM64 binary.
The key is returned by probeGate() which is a JNI native function.
We need to find the JNI_OnLoad -> RegisterNatives -> probeGate implementation.
"""
import zipfile
import struct

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

apk_path = r"C:\Users\zyzmc\Downloads\tartarus (1).apk"

with zipfile.ZipFile(apk_path, "r") as zf:
    so_data = bytearray(zf.read("lib/arm64-v8a/libtartarus_core.so"))

# ELF parsing
e_phoff = struct.unpack_from("<Q", so_data, 32)[0]
e_shoff = struct.unpack_from("<Q", so_data, 40)[0]
e_phnum = struct.unpack_from("<H", so_data, 56)[0]
e_shnum = struct.unpack_from("<H", so_data, 60)[0]
e_shstrndx = struct.unpack_from("<H", so_data, 62)[0]

# Parse segments
segments = []
for i in range(e_phnum):
    off = e_phoff + i * 56
    p_type = struct.unpack_from("<I", so_data, off)[0]
    p_offset = struct.unpack_from("<Q", so_data, off + 8)[0]
    p_vaddr = struct.unpack_from("<Q", so_data, off + 16)[0]
    p_filesz = struct.unpack_from("<Q", so_data, off + 32)[0]
    if p_type == 1:
        segments.append({"vaddr": p_vaddr, "offset": p_offset, "filesz": p_filesz})

def vaddr_to_offset(vaddr):
    for seg in segments:
        if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
            return vaddr - seg["vaddr"] + seg["offset"]
    return None

# Parse sections
sections = []
for i in range(e_shnum):
    off = e_shoff + i * 64
    sh_name = struct.unpack_from("<I", so_data, off)[0]
    sh_type = struct.unpack_from("<I", so_data, off + 4)[0]
    sh_offset = struct.unpack_from("<Q", so_data, off + 24)[0]
    sh_size = struct.unpack_from("<Q", so_data, off + 32)[0]
    sections.append({"name_idx": sh_name, "type": sh_type, "offset": sh_offset, "size": sh_size})

shstrtab = sections[e_shstrndx]
shstrtab_data = so_data[shstrtab["offset"]:shstrtab["offset"] + shstrtab["size"]]

def get_section_name(s):
    end = shstrtab_data.find(b"\x00", s["name_idx"])
    return shstrtab_data[s["name_idx"]:end].decode("ascii", errors="replace")

# Find .rodata
rodata_sec = None
for s in sections:
    if get_section_name(s) == ".rodata":
        rodata_sec = s

# JNI_OnLoad at vaddr 0x1007a4
jni_onload_vaddr = 0x1007a4

print(f"=== Disassembling JNI_OnLoad at {hex(jni_onload_vaddr)} ===")

if HAS_CAPSTONE:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    code = bytes(so_data[jni_onload_vaddr:jni_onload_vaddr + 812])

    # Look for ADRP/ADD pairs that load addresses, and BL calls
    # The RegisterNatives call will have:
    # 1. Load JNIEnv* (x0 from JNI_OnLoad)
    # 2. Load jclass (FindClass result)
    # 3. Load JNINativeMethod array pointer
    # 4. Load method count
    # 5. Call RegisterNatives

    # Find all BL (branch-link) calls
    bl_targets = []
    for insn in md.disasm(code, jni_onload_vaddr):
        if insn.mnemonic == 'bl':
            target = int(insn.op_str.replace('#', ''), 16)
            bl_targets.append((insn.address, target))
            print(f"  BL from {hex(insn.address)} to {hex(target)}")

    # Find ADRP instructions and their paired ADD
    adrp_results = []
    prev_adrp = None
    for insn in md.disasm(code, jni_onload_vaddr):
        if insn.mnemonic == 'adrp':
            prev_adrp = insn
        elif insn.mnemonic == 'add' and prev_adrp:
            # Parse: add xN, xM, #imm
            parts = insn.op_str.split(', ')
            if len(parts) >= 3:
                try:
                    imm = int(parts[2].replace('#', ''), 16)
                    adrp_imm = prev_adrp.operands[1].imm if hasattr(prev_adrp.operands[1], 'imm') else 0
                    page = (prev_adrp.address & ~0xFFF) + (adrp_imm << 12)
                    addr = page + imm
                    print(f"  ADRP+ADD: {hex(prev_adrp.address)}+{hex(insn.address)} -> {hex(addr)}")
                    adrp_results.append(addr)
                except:
                    pass
            prev_adrp = None

    # Now search for JNINativeMethod table in .data.rel.ro
    data_rel_ro_sec = None
    for s in sections:
        if get_section_name(s) == ".data.rel.ro":
            data_rel_ro_sec = s
            break

    if data_rel_ro_sec:
        dr_data = so_data[data_rel_ro_sec["offset"]:data_rel_ro_sec["offset"] + data_rel_ro_sec["size"]]

        # Search for pointers to known method names in .rodata
        rodata = bytes(so_data[rodata_sec["offset"]:rodata_sec["offset"] + rodata_sec["size"]])

        # The JNI method names might be obfuscated. Let's search for any string
        # that looks like a JNI method name (camelCase, reasonable length)
        # by looking at the strings referenced in the code

        # Actually, let's look at the data around each ADRP+ADD target
        print(f"\n=== ADRP+ADD targets ===")
        for addr in adrp_results:
            off = vaddr_to_offset(addr)
            if off and off < len(so_data) - 64:
                # Read 64 bytes
                data = so_data[off:off + 64]
                # Check if it looks like a string
                null_pos = data.find(b'\x00')
                if null_pos > 0 and null_pos < 64:
                    s = data[:null_pos].decode('ascii', errors='replace')
                    if all(c.isprintable() for c in s):
                        print(f"  {hex(addr)}: \"{s}\"")
                    else:
                        # Check if it's a pointer table
                        ptr = struct.unpack_from("<Q", data, 0)[0]
                        print(f"  {hex(addr)}: ptr={hex(ptr)} raw={data[:16].hex()}")
                else:
                    # Check if it's a pointer table
                    ptrs = []
                    for j in range(0, min(64, len(data)), 8):
                        p = struct.unpack_from("<Q", data, j)[0]
                        if p > 0x100000:
                            ptrs.append(hex(p))
                    if ptrs:
                        print(f"  {hex(addr)}: pointers=[{', '.join(ptrs[:8])}]")
                    else:
                        print(f"  {hex(addr)}: raw={data[:32].hex()}")

        # Search for the JNI method table more broadly
        # A JNINativeMethod table has: {char* name, char* signature, void* fnPtr}
        # We need to find a sequence of 3 pointers where name points to a valid string
        # and signature points to a JNI signature like "()Ljava/lang/String;" or "()Z"

        print(f"\n=== Searching for JNINativeMethod table ===")

        # Find all strings in .rodata that look like JNI signatures
        sig_pattern = b"("
        sig_offsets = []
        pos = 0
        while True:
            pos = rodata.find(sig_pattern, pos)
            if pos == -1:
                break
            # Check if it looks like a JNI signature
            end = rodata.find(b'\x00', pos)
            if end != -1 and end - pos < 50:
                s = rodata[pos:end].decode('ascii', errors='replace')
                if ')' in s and all(c in '()ZBCSIJFDBV[L;' or c.isalpha() for c in s):
                    sig_offsets.append((pos, s))
            pos += 1

        print(f"Found {len(sig_offsets)} JNI signatures in .rodata")
        for off, sig in sig_offsets[:20]:
            vaddr = rodata_sec["offset"] + off
            for seg in segments:
                if seg["offset"] <= vaddr < seg["offset"] + seg["filesz"]:
                    vaddr = vaddr - seg["offset"] + seg["vaddr"]
                    break
            print(f"  {hex(vaddr)}: \"{sig}\"")

        # For each signature, search for a pointer to it in .data.rel.ro
        for sig_off, sig_str in sig_offsets:
            sig_file_offset = rodata_sec["offset"] + sig_off
            sig_vaddr = sig_file_offset  # First segment has vaddr=0
            ptr_bytes = struct.pack("<Q", sig_vaddr)

            pos = 0
            while True:
                pos = dr_data.find(ptr_bytes, pos)
                if pos == -1:
                    break

                # Check if there's a name pointer before it (at pos-8)
                # and a function pointer after it (at pos+8)
                if pos >= 8 and pos + 16 <= len(dr_data):
                    name_ptr = struct.unpack_from("<Q", dr_data, pos - 8)[0]
                    fn_ptr = struct.unpack_from("<Q", dr_data, pos + 8)[0]

                    # Read name string
                    name_off = vaddr_to_offset(name_ptr)
                    if name_off and name_off < len(so_data):
                        name_end = so_data.find(b'\x00', name_off)
                        if name_end != -1:
                            name_str = so_data[name_off:name_end].decode('ascii', errors='replace')
                            if len(name_str) > 2 and all(c.isprintable() for c in name_str):
                                fn_off = vaddr_to_offset(fn_ptr)
                                print(f"\n  JNINativeMethod found:")
                                print(f"    name: \"{name_str}\"")
                                print(f"    sig: \"{sig_str}\"")
                                print(f"    fnPtr: {hex(fn_ptr)} (file_offset={hex(fn_off) if fn_off else 'N/A'})")

                                # Disassemble the function
                                if fn_off and HAS_CAPSTONE:
                                    fn_code = bytes(so_data[fn_off:fn_off + 512])
                                    print(f"    First 30 instructions:")
                                    for i, insn in enumerate(md.disasm(fn_code, fn_ptr)):
                                        if i >= 30:
                                            break
                                        print(f"      {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                pos += 1

    # Also try: search the ENTIRE binary for pointer pairs that look like JNINativeMethod
    print(f"\n=== Searching entire binary for JNINativeMethod-like structures ===")
    for sig_off, sig_str in sig_offsets:
        sig_file_offset = rodata_sec["offset"] + sig_off
        ptr_bytes = struct.pack("<Q", sig_file_offset)

        # Search in all data sections
        for s in sections:
            name = get_section_name(s)
            if 'data' in name.lower() and s["size"] > 0:
                data = so_data[s["offset"]:s["offset"] + s["size"]]
                pos = 0
                while True:
                    pos = data.find(ptr_bytes, pos)
                    if pos == -1:
                        break
                    if pos >= 8 and pos + 16 <= len(data):
                        name_ptr = struct.unpack_from("<Q", data, pos - 8)[0]
                        fn_ptr = struct.unpack_from("<Q", data, pos + 8)[0]

                        name_off = vaddr_to_offset(name_ptr)
                        if name_off and name_off < len(so_data):
                            name_end = so_data.find(b'\x00', name_off)
                            if name_end != -1:
                                name_str = so_data[name_off:name_end].decode('ascii', errors='replace')
                                if len(name_str) > 2 and all(c.isprintable() for c in name_str):
                                    fn_off = vaddr_to_offset(fn_ptr)
                                    print(f"\n  Found in {name}:")
                                    print(f"    name: \"{name_str}\"")
                                    print(f"    sig: \"{sig_str}\"")
                                    print(f"    fnPtr: {hex(fn_ptr)}")
                    pos += 1
else:
    print("[!] capstone not installed. Install with: pip install capstone")
