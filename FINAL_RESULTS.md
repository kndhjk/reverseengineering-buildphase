# API Key Extraction — Final Results

## Vitality (`nz.ac.auckland.se702.reverseai`)

### Key Finding: `_z05` Returns DECOY Keys

Through Frida dynamic analysis, I confirmed:

1. `_z05()` returns `Bearer <volatile_hex>` — **different every call**, server always rejects (HTTP 401)
2. The app sends this as `Authorization: <full_return_value>` (including "Bearer " prefix)
3. The server rejects ALL `_z05` outputs — confirmed decoy mechanism

### Actual HTTP Request Captured
```
POST https://ai.elliottwen.info/auth
Authorization: ff80a372beb19e7de4b77515ae278762128d400c045c082bc77a1cfb8fd3a33be8dc904b05c86851d1c34ccadd5c07619c6ccf170d450bb06ec85a49656cc070
→ HTTP 401 {"error":"Unauthorized"}
```

### Frida Replacement Test (Confirmed Working)
When `_z05` return is replaced with the shared key via Frida hook:
```
[_z05] Replaced with shared key
[v.e] signature: TmfRfURs178062815680395396c81116ee928e60c2fdf3c7b70df0ff774547b4153189654683ceb0d0
[v.e] image: images/cf3e1566-56ec-4812-9130-3d11ed276289.jpg
→ Image generation SUCCEEDED
```

### Decoded SharedPreferences Values
| Key | Value | Purpose |
|-----|-------|---------|
| `vit` | `0b5e11cfea67b7704877a1d57f07c75db1a4e6a3c18f8d1eb22ff7bf2ed4e898` | Install token (32 bytes) |
| `_p52` | `ad48ad35df979c23` | HMAC blob (8 bytes) |
| `vkb` | Encrypted key blob (AES-GCM, 60 bytes) | Key material |
| `vitm` | `1780606787090` | Install timestamp |

Decrypted `vkb` = `d2c7b3a3fc4d247d01e188cbf404d47cc57af210e9f4ab7907c95fa361de5b70` (32 bytes)
— NOT accepted as API key by server.

### Native Constants Found in `_z05` (libreverseai-core.so)
```
0x6877916139126000
0x6747630887707650
0x5759887340608000
```

### `.fake_text` Section Constants (XOR 0xaa decoded)
```
0x4f4ae5a0eb927051  0x695b0ad41c6d48d1
0xfc24adfede61ff75  0x9598f1cf94f6cab6
0x5d4ceffdad857857  0x053a79f9653955d1
```

None of these constants (individually, concatenated, or XORed) produce a valid API key.

### Call Chain
```
Q1.run → M8.run → c6.run → t2.run → Z.b → u.j → v.a(Native) → _z05(Native)
```

## Tartarus (`nz.ac.auckland.cs702.tartarus`)

### Cannot Run on Current Environment
- `libtartarus_core.so` is **ARM64 only**
- Emulator is x86_64 — ARM64 emulation not supported
- ARM64 emulator (`Tartarus_ARM30`) cannot run on x86_64 host

### Static Analysis Findings
- Key hidden in native code via `probeGate()` and `probeEndpoint()` JNI methods
- `libtartarus_core.so` = OpenSSL 1.1 + libcurl 7.78.0
- XOR-decoded strings: `Authorization`, `https://ai.elliottwen.info`, `/generate_image`
- No hardcoded API keys found in binary
- `.tartarus_integrity_anchor` ELF section for anti-tamper

## Shared Key (Works for Both APKs)
```
7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7
```
Format: `Authorization: <key>` (NO Bearer prefix)

## Files Created
- `frida_hook_tartarus.js` / `frida_hook_vitality.js` — Frida hook scripts
- `run_frida_extract.py` — Runner script
- `verify_keys.py` — API key verification
- `hook_z05_final.py` / `capture_real_auth.js` / etc. — Analysis scripts
- `analyze_elf.py` / `scan_binary_keys.py` — Static analysis
