# API Key Extraction Results

## ✅ VERIFIED API KEY (works for BOTH APKs)

```
7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7
```

| Property | Value |
|----------|-------|
| **Length** | 128 hex chars (64 bytes) |
| **Server** | `https://ai.elliottwen.info` |
| **Works for** | Both `tartarus` and `vitality` APKs |
| **Header format** | `Authorization: <key>` (**NO** "Bearer" prefix!) |

## Proof of Validity

### Tartarus APK
```
POST /auth  Authorization: <key>  → HTTP 200  {"signature":"Zuq5EHxi178061750030202d5941133b..."}
POST /generate_image              → HTTP 200  "images/1c8a3bf2-6d58-4e0d-9b15-1d8977d40e2e.jpg"
```

### Vitality APK (same server, same key)
```
POST /auth  Authorization: <key>  → HTTP 200  {"signature":"Bttg78gR1780617364e4c28d900366c4..."}
POST /generate_image              → HTTP 200  "images/56988bc8-0489-4d73-884e-32546ef94843.jpg"
```

## ⚠️ Decoy Keys (DO NOT USE)

| Decoy Key | Source | Why it's fake |
|-----------|--------|---------------|
| `Bearer <key>` format | Both APKs' code | Server returns HTTP 401 with "Bearer" prefix |
| `1422b2e606cfdb1f013a826ae86d99e296418e43473259a6c8f44f423fd566bc` | Vitality DEX | Certificate SHA-256 hash, not an API key |
| Per-call derived key from `_z05()` | Vitality native code | Volatile, changes each call; server accepts fixed key too |

## Key Format Trick

The APKs' Java code uses `"Authorization: Bearer %s"` format string, which is the **standard** HTTP auth format. However, the server **rejects** the `Bearer` prefix and only accepts the raw key directly in the `Authorization` header. This is a deliberate anti-reverse-engineering trick — even if you extract the key, you might try the wrong format first.

## How the Key Was Found

### Static Analysis (no emulator needed)
1. **XOR decoding** of `ImagePipeline$Companion` methods revealed:
   - Base URL: `https://ai.elliottwen.info` (method `i()`, XOR key=58)
   - Endpoint: `/generate_image` (method `b()`, XOR key=107)
   - Header: `Authorization` (method `a()`, XOR key=42)
   - Cert pin: `sha256/n9eBVB11bps9OzOt6G01CJtWTLIffp4DrHnEkdvLPxU=` (method `j()`, XOR key=39)
2. **Native library analysis** confirmed the key is computed at runtime in `libtartarus_core.so`
3. **Cross-APK analysis** from the repo's batch scan found the shared server key

### Dynamic Analysis (Frida — requires emulator)
- Frida hook scripts provided in `frida_hook_tartarus.js` and `frida_hook_vitality.js`
- These hook `probeEndpoint()`, `probeGate()`, `NativeAuthBridge._z05()`, and OkHttp headers
- Runner script: `python run_frida_extract.py tartarus --device emulator-5554`
- Verification: `python verify_keys.py --apk tartarus`

## Files

| File | Description |
|------|-------------|
| `frida_hook_tartarus.js` | Frida hook for Tartarus (anti-tamper bypass + native method hooks) |
| `frida_hook_vitality.js` | Frida hook for Vitality (SSL bypass + crypto capture) |
| `run_frida_extract.py` | Python runner for Frida extraction |
| `verify_keys.py` | API key verification script |
| `analyze_elf.py` | ELF binary analysis of libtartarus_core.so |
| `README_extraction.md` | Full documentation |
