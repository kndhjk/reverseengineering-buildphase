#!/usr/bin/env python3
"""
Disassemble libtartarus_core.so JNI_OnLoad to find RegisterNatives
and locate the native method implementations (probeEndpoint, probeGate, etc.).
Then disassemble those functions to find the key material.
"""
import zipfile
import struct
try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[!] capstone not installed, using manual ARM64 decoding")

apk_path = r"C:\Users\zyzmc\Downloads\tartarus (1).apk"

with zipfile.ZipFile(apk_path, "r") as zf:
    so_data = bytearray(zf.read("lib/arm64-v8a/libtartarus_core.so"))

# ELF header parsing
e_shoff = struct.unpack_from("<Q", so_data, 40)[0]
e_shnum = struct.unpack_from("<H", so_data, 60)[0]
e_shstrndx = struct.unpack_from("<H", so_data, 62)[0]
sh_size = 64

sections = []
for i in range(e_shnum):
    off = e_shoff + i * sh_size
    sh_name = struct.unpack_from("<I", so_data, off)[0]
    sh_type = struct.unpack_from("<I", so_data, off + 4)[0]
    sh_offset = struct.unpack_from("<Q", so_data, off + 24)[0]
    sh_size_val = struct.unpack_from("<Q", so_data, off + 32)[0]
    sections.append({"name_idx": sh_name, "type": sh_type, "offset": sh_offset, "size": sh_size_val})

shstrtab = sections[e_shstrndx]
shstrtab_data = so_data[shstrtab["offset"]:shstrtab["offset"] + shstrtab["size"]]

def get_section_name(s):
    end = shstrtab_data.find(b"\x00", s["name_idx"])
    return shstrtab_data[s["name_idx"]:end].decode("ascii", errors="replace")

# Find .text section
text_sec = None
rodata_sec = None
for s in sections:
    name = get_section_name(s)
    if name == ".text":
        text_sec = s
    elif name == ".rodata":
        rodata_sec = s

print(f".text: offset={hex(text_sec['offset'])} size={hex(text_sec['size'])}")
print(f".rodata: offset={hex(rodata_sec['offset'])} size={hex(rodata_sec['size'])}")

# JNI_OnLoad address from ELF analysis: 0x1007a4
# But we need the file offset. Let's find the segment mapping.
# Parse program headers to get virtual address to file offset mapping
e_phoff = struct.unpack_from("<Q", so_data, 32)[0]
e_phnum = struct.unpack_from("<H", so_data, 56)[0]
ph_size = 56

segments = []
for i in range(e_phnum):
    off = e_phoff + i * ph_size
    p_type = struct.unpack_from("<I", so_data, off)[0]
    p_offset = struct.unpack_from("<Q", so_data, off + 8)[0]
    p_vaddr = struct.unpack_from("<Q", so_data, off + 16)[0]
    p_filesz = struct.unpack_from("<Q", so_data, off + 32)[0]
    p_memsz = struct.unpack_from("<Q", so_data, off + 40)[0]
    if p_type == 1:  # PT_LOAD
        segments.append({"vaddr": p_vaddr, "offset": p_offset, "filesz": p_filesz, "memsz": p_memsz})
        print(f"PT_LOAD: vaddr={hex(p_vaddr)} offset={hex(p_offset)} filesz={hex(p_filesz)}")

def vaddr_to_offset(vaddr):
    for seg in segments:
        if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
            return vaddr - seg["vaddr"] + seg["offset"]
    return None

# JNI_OnLoad at vaddr 0x1007a4
jni_onload_vaddr = 0x1007a4
jni_onload_offset = vaddr_to_offset(jni_onload_vaddr)
print(f"\nJNI_OnLoad: vaddr={hex(jni_onload_vaddr)} file_offset={hex(jni_onload_offset)}")

# Disassemble JNI_OnLoad
if HAS_CAPSTONE:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Disassemble 200 instructions from JNI_OnLoad
    code = bytes(so_data[jni_onload_offset:jni_onload_offset + 812])

    print(f"\n=== JNI_OnLoad disassembly (looking for RegisterNatives call) ===")
    register_natives_addr = None
    method_table_addrs = []

    for insn in md.disasm(code, jni_onload_vaddr):
        # Look for ADRP + ADD patterns that load addresses
        # Also look for BL (branch-link) calls
        if insn.mnemonic == 'bl':
            print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        elif insn.mnemonic in ('adrp', 'add'):
            print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        elif 'x0' in insn.op_str and insn.mnemonic in ('str', 'ldr', 'mov'):
            print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

    # Now disassemble more broadly to find the string "probeEndpoint" or similar
    # Search the entire .text for function prologues near string references
    print("\n=== Searching for JNINativeMethod table (name, sig, fnPtr) ===")
    # JNINativeMethod is: {char* name, char* signature, void* fnPtr}
    # Each entry is 3 pointers = 24 bytes on 64-bit
    # We need to find pointers to strings like "probeEndpoint", "()Ljava/lang/String;"

    # First find the strings in .rodata
    rodata = bytes(so_data[rodata_sec["offset"]:rodata_sec["offset"] + rodata_sec["size"]])

    target_strings = [
        b"probeEndpoint",
        b"probeGate",
        b"warmupNative",
        b"readPalette",
        b"composeFrame",
        b"checkPeer",
        b"routeBase",
        b"inspectRuntime",
    ]

    string_vaddrs = {}
    for s in target_strings:
        idx = rodata.find(s)
        if idx != -1:
            # The string is at file offset rodata_sec["offset"] + idx
            # Convert to vaddr
            str_file_offset = rodata_sec["offset"] + idx
            str_vaddr = None
            for seg in segments:
                if seg["offset"] <= str_file_offset < seg["offset"] + seg["filesz"]:
                    str_vaddr = str_file_offset - seg["offset"] + seg["vaddr"]
                    break
            if str_vaddr:
                string_vaddrs[s.decode()] = str_vaddr
                print(f"  '{s.decode()}' at vaddr={hex(str_vaddr)} file_offset={hex(str_file_offset)}")

    # Now search for these vaddrs in the .data.rel.ro section (where JNI method tables are)
    # Find .data.rel.ro
    data_rel_ro_sec = None
    for s in sections:
        name = get_section_name(s)
        if name == ".data.rel.ro":
            data_rel_ro_sec = s
            break

    if data_rel_ro_sec:
        print(f"\n.data.rel.ro: offset={hex(data_rel_ro_sec['offset'])} size={hex(data_rel_ro_sec['size'])}")
        data = so_data[data_rel_ro_sec["offset"]:data_rel_ro_sec["offset"] + data_rel_ro_sec["size"]]

        # Search for pointers to our strings (8-byte pointers)
        for name, vaddr in string_vaddrs.items():
            ptr_bytes = struct.pack("<Q", vaddr)
            idx = 0
            while True:
                pos = data.find(ptr_bytes, idx)
                if pos == -1:
                    break
                # Found a pointer to the string name
                # JNINativeMethod table: {name_ptr, sig_ptr, fnPtr_ptr}
                # The name_ptr is at pos, sig_ptr at pos+8, fnPtr at pos+16
                entry_offset = data_rel_ro_sec["offset"] + pos
                if pos + 24 <= len(data):
                    sig_ptr = struct.unpack_from("<Q", data, pos + 8)[0]
                    fn_ptr = struct.unpack_from("<Q", data, pos + 16)[0]

                    # Read the signature string
                    sig_file_offset = vaddr_to_offset(sig_ptr)
                    if sig_file_offset and sig_file_offset < len(so_data):
                        sig_end = so_data.find(b"\x00", sig_file_offset)
                        sig_str = so_data[sig_file_offset:sig_end].decode("ascii", errors="replace")

                        print(f"\n  JNINativeMethod found:")
                        print(f"    name: '{name}' (ptr={hex(vaddr)})")
                        print(f"    signature: '{sig_str}' (ptr={hex(sig_ptr)})")
                        print(f"    fnPtr: {hex(fn_ptr)}")

                        # Disassemble the native function
                        fn_offset = vaddr_to_offset(fn_ptr)
                        if fn_offset and HAS_CAPSTONE:
                            print(f"    fn_offset: {hex(fn_offset)}")
                            fn_code = bytes(so_data[fn_offset:fn_offset + 256])
                            print(f"    First 20 instructions:")
                            for i, insn in enumerate(md.disasm(fn_code, fn_ptr)):
                                if i >= 20:
                                    break
                                print(f"      {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                idx = pos + 1
else:
    # Without capstone, just search for the JNINativeMethod table
    print("\n=== Searching for JNINativeMethod table (manual) ===")
    rodata = bytes(so_data[rodata_sec["offset"]:rodata_sec["offset"] + rodata_sec["size"]])

    target_strings = [b"probeEndpoint\x00", b"probeGate\x00", b"warmupNative\x00", b"readPalette\x00"]
    for s in target_strings:
        idx = rodata.find(s)
        if idx != -1:
            print(f"  Found '{s.decode()}' at rodata+{hex(idx)}")
