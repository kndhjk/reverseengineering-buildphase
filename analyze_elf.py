#!/usr/bin/env python3
"""Analyze ELF structure of libtartarus_core.so to find JNI and custom functions."""
import zipfile
import struct

apk_path = r"C:\Users\zyzmc\Downloads\tartarus (1).apk"

with zipfile.ZipFile(apk_path, "r") as zf:
    so_data = zf.read("lib/arm64-v8a/libtartarus_core.so")

# Parse ELF header (64-bit)
e_type = struct.unpack_from("<H", so_data, 16)[0]
e_machine = struct.unpack_from("<H", so_data, 18)[0]
e_entry = struct.unpack_from("<Q", so_data, 24)[0]
e_shoff = struct.unpack_from("<Q", so_data, 40)[0]
e_shnum = struct.unpack_from("<H", so_data, 60)[0]
e_shstrndx = struct.unpack_from("<H", so_data, 62)[0]

print(f"ELF: type={e_type} machine={e_machine} entry={hex(e_entry)} sections={e_shnum}")

# Parse section headers
sh_size = 64
sections = []
for i in range(e_shnum):
    off = e_shoff + i * sh_size
    sh_name = struct.unpack_from("<I", so_data, off)[0]
    sh_type = struct.unpack_from("<I", so_data, off + 4)[0]
    sh_offset = struct.unpack_from("<Q", so_data, off + 24)[0]
    sh_size_val = struct.unpack_from("<Q", so_data, off + 32)[0]
    sh_link = struct.unpack_from("<I", so_data, off + 40)[0]
    sections.append({"name_idx": sh_name, "type": sh_type, "offset": sh_offset, "size": sh_size_val, "link": sh_link})

# Section name string table
shstrtab = sections[e_shstrndx]
shstrtab_data = so_data[shstrtab["offset"]:shstrtab["offset"] + shstrtab["size"]]

def get_section_name(s):
    end = shstrtab_data.find(b"\x00", s["name_idx"])
    return shstrtab_data[s["name_idx"]:end].decode("ascii", errors="replace")

# Find .dynsym and .dynstr
dynsym_sec = dynstr_sec = None
for s in sections:
    name = get_section_name(s)
    if name == ".dynsym":
        dynsym_sec = s
    elif name == ".dynstr":
        dynstr_sec = s

print(f".dynsym: offset={hex(dynsym_sec['offset'])} size={hex(dynsym_sec['size'])}")
print(f".dynstr: offset={hex(dynstr_sec['offset'])} size={hex(dynstr_sec['size'])}")

dynstr_data = so_data[dynstr_sec["offset"]:dynstr_sec["offset"] + dynstr_sec["size"]]

sym_size = 24
num_symbols = dynsym_sec["size"] // sym_size
print(f"Symbol count: {num_symbols}")

# Parse all symbols
jni_syms = []
custom_syms = []
all_exported = []

std_prefixes = [
    "curl_", "SSL_", "EVP_", "RSA_", "EC_", "BN_", "X509_", "OPENSSL_", "CRYPTO_",
    "BIO_", "PEM_", "PKCS", "HMAC_", "SHA", "MD5", "AES_", "DES_",
    "DSA_", "DH_", "ECDSA_", "ECDH_", "RAND_", "ERR_", "OBJ_", "ASN1_",
    "STACK_", "BUF_", "MEM_", "LHASH_", "TXT_DB_", "UI_", "CONF_", "ENGINE_",
    "OCSP_", "TS_", "CMS_", "SRP_", "GOST_", "s2i_", "i2s_", "i2d_", "d2i_",
    "a2i_", "i2a_", "sk_", "OPENSSL_LH_", "CRYPTO_", "ossl_", "impl_",
]

for i in range(num_symbols):
    off = dynsym_sec["offset"] + i * sym_size
    st_name_idx = struct.unpack_from("<I", so_data, off)[0]
    st_info = so_data[off + 4]
    st_bind = st_info >> 4
    st_type = st_info & 0xF
    st_shndx = struct.unpack_from("<H", so_data, off + 6)[0]
    st_value = struct.unpack_from("<Q", so_data, off + 8)[0]
    st_size = struct.unpack_from("<Q", so_data, off + 16)[0]

    if st_name_idx >= len(dynstr_data):
        continue
    name_end = dynstr_data.find(b"\x00", st_name_idx)
    name = dynstr_data[st_name_idx:name_end].decode("ascii", errors="replace")
    if not name or len(name) < 3:
        continue

    if "Java_" in name or "JNI_OnLoad" in name:
        jni_syms.append((name, st_value, st_size))

    if st_bind == 1 and st_type == 2 and st_shndx != 0 and st_value > 0:
        all_exported.append((name, st_value, st_size))
        if not any(name.startswith(p) for p in std_prefixes) and not name.startswith("__"):
            custom_syms.append((name, st_value, st_size))

print("\n=== JNI FUNCTIONS ===")
for name, addr, size in jni_syms:
    print(f"  {name}  @ {hex(addr)}  size={size}")

print("\n=== CUSTOM (NON-LIBRARY) EXPORTED FUNCTIONS ===")
for name, addr, size in custom_syms:
    print(f"  {name}  @ {hex(addr)}  size={size}")

# Now try to read the data around the JNI functions
print("\n=== DISASSEMBLING JNI FUNCTION PROLOGUES (first 64 bytes) ===")
for name, addr, size in jni_syms:
    if addr > 0 and addr < len(so_data) - 64:
        code = so_data[addr:addr + 64]
        hexdump = " ".join(f"{b:02x}" for b in code[:64])
        print(f"\n  {name} @ {hex(addr)}:")
        print(f"    {hexdump}")
        # ARM64 instructions are 4 bytes each - show first 16 instructions
        print(f"    Instructions:")
        for j in range(0, min(64, len(code)), 4):
            insn = struct.unpack_from("<I", code, j)[0]
            print(f"      +{j:3d}: {insn:08x}")
