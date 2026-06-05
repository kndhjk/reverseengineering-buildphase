# CS702/SE702 Reverse Engineering CTF Challenge — API Key Extraction

## Context

This repository documents the analysis of two Android APKs (`tartarus.apk` and `vitality.apk`) from the **University of Auckland CS702/SE702 Security course** reverse engineering assignment. The assignment is part of an authorized educational CTF (Capture The Flag) exercise where students are tasked with extracting API keys hidden inside obfuscated Android applications.

**Reference repository**: [kndhjk/reverseengineering-buildphase](https://github.com/kndhjk/reverseengineering-buildphase) — the teaching platform that contains the APKs, analysis tools, and grading infrastructure.

**Target server**: `https://ai.elliottwen.info` — the assignment's grading/AI image generation server.

**Assignment goal**: Extract each APK's unique API key that authenticates against the server. The server accepts POST requests to `/auth` with the key in the `Authorization` header, returning a `signature` used for `/generate_image`.

## Key Format Discovery

The server accepts: `Authorization: <key>` (128 hex chars, NO "Bearer" prefix)

The APKs deliberately use `Authorization: Bearer <key>` format in their code, but the server **rejects** the `Bearer` prefix. This is a deliberate anti-RE trap.

## Shared Key (Known Working)

Both APKs accept this key (from teambeta.apk's SharedPreferences XOR decoding):

```
7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7
```

Verification:
```bash
curl -X POST https://ai.elliottwen.info/auth \
  -H "Authorization: 7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7" \
  -H "Content-Type: application/json" \
  -d '{}'
# Returns: {"signature":"..."} — HTTP 200
```

## UNRESOLVED: Per-APK Independent Keys

Each APK is expected to have its own unique API key (128 hex chars) that works independently. The shared key above works for both, but the assignment likely expects each APK's own key.

### Vitality (`nz.ac.auckland.se702.reverseai`)

**Status**: `_z05` confirmed as decoy generator. Independent key NOT found.

**Architecture**:
- `NativeAuthBridge._z05([B[B[B)String` — JNI native method, returns `Bearer <key>`
- `NativeAuthBridge._z06([B)V` — processes auth response
- Native libs: `libreverseai-core.so`, `libreverseai-crypto.so`

**Why `_z05` is a decoy**:
1. Returns different key every call (even with identical inputs)
2. Uses `clock_gettime()` + internal counter as randomization source (100+ calls per invocation)
3. Server rejects ALL `_z05` outputs (HTTP 401)
4. Even with correct decrypted inputs (32-byte key blob + 8-byte HMAC), still returns fake keys
5. Disassembly shows MOVABS constants (`0x6877916139126000`, `0x6747630887707650`, `0x5759887340608000`) used in XOR, but result is always different

**Attempted approaches**:
- ✅ Bypassed integrity checks (`X5.i`, `G4.e`, `F0.f` → return true)
- ✅ Decrypted SharedPreferences values (vkb, vit, _p52)
- ✅ Injected correct decrypted key blob (32 bytes) and HMAC (8→32 bytes) into `_z05`
- ✅ Froze `clock_gettime` — first call deterministic, subsequent calls still random (counter)
- ✅ Replaced `_z05` Java return with shared key — app works, confirming key flow
- ✅ Traced full call chain: `Q1.run → M8.run → c6.run → t2.run → Z.b → u.j → _z05`
- ❌ Cannot find independent key — `_z05` is fundamentally a decoy generator

**Decrypted SharedPreferences values**:
| Key | Value | Purpose |
|-----|-------|---------|
| `vit` | `0b5e11cfea67b7704877a1d57f07c75db1a4e6a3c18f8d1eb22ff7bf2ed4e898` | Install token (32 bytes) |
| `_p52` | `ad48ad35df979c23` | HMAC blob (8 bytes) |
| `vkb` | `d2c7b3a3fc4d247d01e188cbf404d47cc57af210e9f4ab7907c95fa361de5b70` | Decrypted key blob (32 bytes) |
| `vitm` | `1780606787090` | Install timestamp |

### Tartarus (`nz.ac.auckland.cs702.tartarus`)

**Status**: Cannot run — ARM64 only. Independent key NOT found.

**Architecture**:
- `AssetProbe.probeEndpoint()` → returns URL (JNI native)
- `AssetProbe.probeGate()` → returns auth token (JNI native)
- `libtartarus_core.so` — OpenSSL 1.1 + libcurl 7.78.0, ARM64 only
- Key is entirely in native code, invisible to DEX analysis

**Why extraction failed**:
- `libtartarus_core.so` only has ARM64 architecture
- Emulator is x86_64 — ARM64 emulation not supported by QEMU2
- ARM64 emulator (`Tartarus_ARM30`) cannot run on x86_64 host
- App crashes immediately on x86_64 emulator (native lib architecture mismatch)

**Static analysis findings**:
- XOR-decoded strings: `Authorization` (key=42), `https://ai.elliottwen.info` (key=58), `/generate_image` (key=107), `sha256/n9eBVB11bps9OzOt6G01CJtWTLIffp4DrHnEkdvLPxU=` (cert pin, key=39)
- No hardcoded API keys in DEX or .so
- JNI methods registered dynamically via `RegisterNatives` (not exported as `Java_*` symbols)
- Anti-tamper: `RuntimeProbe.inspectRuntime()`, root detection, `/proc/self/maps` scanning

## Problem Summary

| Issue | Impact |
|-------|--------|
| `_z05` is a decoy key generator | Cannot extract vitality's real key via Frida |
| `libtartarus_core.so` is ARM64 only | Cannot run tartarus on x86_64 emulator |
| `clock_gettime` + counter randomization | `_z05` output non-deterministic even with frozen time |
| JNI method names obfuscated | Static analysis cannot find `probeGate`/`probeEndpoint` implementations |
| Anti-Frida detection | App crashes when Frida is attached (tartarus) |
| Integrity checks run before hooks install | `_y01`/`_y02`/`_y03` fail before Frida can intercept |

## Files

### Frida Scripts
| File | Target | Purpose |
|------|--------|---------|
| `frida_hook_tartarus.js` | Tartarus | Anti-tamper bypass + native method hooks |
| `frida_hook_vitality.js` | Vitality | SSL bypass + crypto capture + _z05 hook |
| `bypass_integrity.js` | Vitality | Bypass X5.i/G4.e/F0.f + _y01/_y02/_y03 SP fallback |
| `bypass_early.js` | Vitality | Early integrity bypass before onCreate |
| `capture_full_hmac.js` | Vitality | Capture full 32-byte HMAC from Mac.doFinal |
| `capture_real_auth.js` | Vitality | Capture actual Authorization header from HTTP |
| `capture_http.js` | Vitality | Hook URL/HttpsURLConnection for HTTP capture |
| `disasm_z05_runtime.js` | Vitality | Disassemble _z05 at runtime, find MOVABS/XOR/CALL |
| `freeze_time.js` | Vitality | Freeze clock_gettime to test time dependency |
| `hook_class_load.js` | Vitality | Hook via RegisterNatives trigger |
| `hook_inner_fn.js` | Vitality | Hook _z05 inner functions |
| `hook_newstringutf.js` | Vitality | Hook JNI NewStringUTF inside _z05 |
| `hook_on_load.js` | Vitality | Hook System.loadLibrary for early interception |
| `hook_oncreate.js` | Vitality | Hook Application.onCreate |
| `hook_uj.js` | Vitality | Hook u.j (calls _z05) with full trace |
| `hook_va.js` | Vitality | Hook v.a to trace key flow |
| `inject_correct_inputs.js` | Vitality | Inject correct decrypted inputs into _z05 |
| `inject_decrypted_blob.js` | Vitality | Replace arg1 with 32-byte decrypted key blob |
| `inject_hmac.js` | Vitality | Inject HMAC blob into _z05 arg2 |
| `native_trace_z05.js` | Vitality | Native-level _z05 argument tracing |
| `native_y_hooks.js` | Vitality | Native hooks for _y01/_y02/_y03 |
| `replace_arg2.js` | Vitality | Replace _z05 arg2 with correct HMAC |
| `replace_z05.js` | Vitality | Replace _z05 return with shared key |
| `safe_z05.js` | Vitality | Safe _z05 hook (null-safe arg reading) |
| `sync_hooks.js` | Vitality | Synchronous hooks via performNow |
| `trace_fallback.js` | Vitality | Trace full auth flow after _z05 failure |
| `trace_full_flow.js` | Vitality | Trace complete HTTP request/response |
| `trace_random_source.js` | Vitality | Identify clock_gettime as random source |
| `trace_xor_detail.js` | Vitality | Detailed _z05 XOR/MOVABS/CALL analysis |
| `trace_z05_xor.js` | Vitality | Trace _z05 XOR operations |

### Python Scripts
| File | Purpose |
|------|---------|
| `run_frida_extract.py` | Generic Frida runner (spawn, inject, collect) |
| `verify_keys.py` | Test keys against /auth endpoint |
| `analyze_elf.py` | ELF binary analysis of .so files |
| `scan_binary_keys.py` | Search .so files for key material |
| `disasm_jni.py` | Disassemble JNI_OnLoad to find RegisterNatives |
| `extract_tartarus_key_static.py` | Static analysis of tartarus DEX + .so |
| `hook_vitality_final.py` | Python-based vitality hook runner |
| `hook_tartarus_live.py` | Python-based tartarus hook runner |
| `hook_z05_final.py` | Hook _z05 with full I/O capture |
| `find_real_key.py` | Test various key derivation approaches |
| `find_real_key2.py` | Hook all crypto to find real key |
| `decode_keys.py` | Decode XOR keys from DEX |
| `deep_analysis.py` | Deep static analysis of both APKs |
| `decrypt_vkb.py` | Decrypt vkb key blob via Cipher hooks |

### Documentation
| File | Purpose |
|------|---------|
| `README.md` | This file — comprehensive challenge documentation |
| `README_extraction.md` | Frida extraction procedures |
| `RESULTS.md` | Detailed analysis results |
| `FINAL_RESULTS.md` | Final findings summary |

## How to Continue (for Codex)

### To extract vitality's independent key:
1. The key is NOT in `_z05` — that's a confirmed decoy
2. Look for alternative key sources in the native code:
   - Functions called by `v.a()` before/after `_z05`
   - The `u.j()` coroutine method — inspect its full bytecode
   - Class `p.j()` — second auth attempt uses different code path
   - The `.fake_text` section of `libreverseai-core.so` (XOR 0xaa decoded) contains embedded constants
3. The `_z05` function expects arg1=32 bytes (decrypted key blob) and arg2=32 bytes (full HMAC-SHA256, not truncated 8 bytes)
4. Try hooking `Mac.doFinal` during `onCreate()` to capture the full 32-byte HMAC before truncation

### To extract tartarus's independent key:
1. Need ARM64 device or cloud ARM64 emulator
2. Use Frida to hook `probeEndpoint()` and `probeGate()` JNI methods
3. Or use Ghidra/IDA Pro to disassemble `libtartarus_core.so` and find the key in the `probeGate` function
4. The repo's `scripts/tartarus_hook.py` and `run_tartarus.py` have working hook templates

### Key verification command:
```bash
curl -s -X POST https://ai.elliottwen.info/auth \
  -H "Authorization: <KEY_HERE>" \
  -H "Content-Type: application/json" \
  -d '{}' | python -m json.tool
```
Returns `{"signature": "..."}` on success, `{"error": "Unauthorized"}` on failure.

## Environment

- **OS**: Windows 10 Enterprise 10.0.19045
- **Python**: 3.14.5
- **Frida**: 16.5.9 (Python) / frida-tools 12.5.0
- **Frida Server**: 16.x on emulator-5554, 17.10.1 on emulator-5556
- **Emulators**: emulator-5554 (x86_64, Android 11), emulator-5556 (x86_64)
- **APK targets**: tartarus (ARM64 only), vitality (ARM64 + x86_64)
- **Android SDK**: `C:\Users\zyzmc\AppData\Local\Android\Sdk`
