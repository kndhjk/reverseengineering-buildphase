import base64
import binascii

print("=" * 80)
print("  DECODING CRITICAL KEY MATERIAL FROM VITALITY APK")
print("=" * 80)

# 1. The HEX key found in DEX strings
hex_key = "1422b2e606cfdb1f013a826ae86d99e296418e43473259a6c8f44f423fd566bc"
print(f"\n1. HEX KEY (from DEX const-string):")
print(f"   Raw hex: {hex_key}")
print(f"   Length: {len(hex_key)} hex chars = {len(hex_key)//2} bytes")
print(f"   Bytes: {binascii.unhexlify(hex_key)}")
print(f"   This is a 256-bit (32-byte) key!")

# 2. The B64 string that's actually hex
b64_data = "00000000000000000000000000000000117c3a309476becd5d064d4206bff43ada68bd71fbcc6eee821ed68e41d83f855ebbfb5a9be392c7a9cc77ffd36c6563f6da4619d944b4e35ae3fb40731b8e18b58d62053c0e431925a2ed723815842fcc6fb232b227b85c827bde038a37fdb2a23c39738cb8f880d4ad458674eef145"
print(f"\n2. B64 STRING (actually hex-encoded data):")
print(f"   Raw: {b64_data[:80]}...")
print(f"   Length: {len(b64_data)} chars")
print(f"   As bytes: {len(b64_data)//2} bytes")

# Try decoding as hex
try:
    decoded_hex = binascii.unhexlify(b64_data)
    print(f"   Decoded hex ({len(decoded_hex)} bytes): {decoded_hex.hex()}")
    print(f"   First 16 bytes (IV/nonce?): {decoded_hex[:16].hex()}")
    print(f"   Bytes 16-48 (key?): {decoded_hex[16:48].hex()}")
    print(f"   Bytes 48-80: {decoded_hex[48:80].hex()}")
    print(f"   Last 32 bytes: {decoded_hex[-32:].hex()}")
except Exception as e:
    print(f"   Error decoding as hex: {e}")

# 3. SO_HEX from libreverseai-core.so
so_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0df"
print(f"\n3. SO_HEX from libreverseai-core.so:")
print(f"   Raw: {so_hex}")
print(f"   Length: {len(so_hex)} hex chars = {len(so_hex)//2} bytes")
decoded_so = binascii.unhexlify(so_hex)
print(f"   Decoded: {decoded_so.hex()}")
print(f"   Pattern: 0x00-0x1f ascending, then 0xfe-0xdf descending")
print(f"   This is a 64-byte lookup table / S-box / key schedule constant")

# 4. Certificate pin hashes
cert_pins = [
    "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
    "sha256/Y+qVcAbTbJUkv0N0yR2D7+qaY+yBS8BGRAG0U5ukZec=",
    "sha256/kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
    "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
    "sha256/zCTnfLwLKbS9S2sbp+uFz4KZOocFvXxkV06Ce9O5M2w=",
]
print(f"\n4. CERTIFICATE PINNING HASHES:")
for pin in cert_pins:
    # Remove sha256/ prefix and decode
    b64_part = pin.replace("sha256/", "")
    try:
        raw = base64.b64decode(b64_part)
        print(f"   {pin}")
        print(f"     -> SHA256: {raw.hex()}")
    except:
        print(f"   {pin} (decode error)")

# 5. Native crypto functions
print(f"\n5. NATIVE CRYPTO FUNCTIONS (libreverseai-crypto.so):")
print(f"   vitality_aes_xts_decrypt_sector  - AES-XTS decryption (disk encryption style)")
print(f"   vitality_argon2id_derive_key     - Argon2id key derivation (password hashing)")
print(f"   vitality_curve25519_x25519_keygen - Curve25519 key exchange")
print(f"   vitality_ed25519_sign_message    - Ed25519 digital signatures")

# 6. Key-related DEX strings
print(f"\n6. KEY-RELATED DEX STRINGS IN VITALITY:")
print(f"   ANDROID_KEY_STORE               - Android Keystore usage")
print(f"   PREFS_CANONICAL_TAG_BLOB_KEY    - SharedPreferences key for tag blob")
print(f"   PREFS_INSTALL_TIME_MS_KEY       - SharedPreferences key for install time")
print(f"   PREFS_INSTALL_TOKEN_BLOB_KEY    - SharedPreferences key for install token")
print(f"   cachedInstallToken              - Cached install token field")
print(f"   INSTALL_TOKEN_LEN_BYTES         - Install token length constant")
print(f"   NativeAuthBridge                - JNI bridge for native auth")
print(f"   Invalid auth endpoint.          - Auth endpoint validation")
print(f"   Authentication failed.          - Auth failure message")
print(f"   Authenticating and generating image... - Auth + image gen flow")

print(f"\n{'='*80}")
print(f"  ANALYSIS SUMMARY")
print(f"{'='*80}")
print(f"""
VITALITY APK (nz.ac.auckland.se702.reverseai):
  CRITICAL FINDINGS:
  - 256-bit HEX KEY in DEX: {hex_key}
  - 160-byte hex blob with 16-byte zero prefix (likely encrypted key material)
  - 64-byte S-box/lookup table in native lib
  - Certificate pinning with 5 pinned certs
  - Native crypto: AES-XTS, Argon2id, Curve25519, Ed25519
  - Uses Android Keystore + SharedPreferences for token storage
  - Has NativeAuthBridge JNI class for crypto operations
  - Install token system with PREFS_INSTALL_TOKEN_BLOB_KEY

TARTARUS APK (nz.ac.auckland.cs702.tartarus):
  CRITICAL FINDINGS:
  - libtartarus_core.so contains full OpenSSL/libcurl stack
  - No hardcoded API keys or hex keys found in DEX
  - 325 "key candidates" but ALL are false positives (library strings)
  - Uses HTTP proxy settings, Bearer auth: 'auth=Bearer %s'
  - No assets folder content
  - XOR methods exist but use numeric string indices (string table lookups)
  - Build path leak: /Users/rying/repo/openssl-curl-android/
""")
