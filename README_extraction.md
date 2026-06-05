# Frida API Key Extraction — Tartarus & Vitality APKs

## Overview

This toolkit extracts API keys from two CTF-style Android APKs from the University of Auckland security course. Both APKs communicate with `https://ai.elliottwen.info` and hide their API keys behind native code, obfuscation, and anti-tamper protections.

**⚠️ Warning**: Both APKs likely contain **decoy/fake keys** designed to mislead reverse engineers. The verification script tests each captured key against the live API to distinguish real keys from fakes.

## Target APKs

| APK | Package | Key Hiding Method |
|-----|---------|-------------------|
| **Tartarus** | `nz.ac.auckland.cs702.tartarus` | Native code in `libtartarus_core.so` (JNI methods return endpoint/key) |
| **Vitality** | `nz.ac.auckland.se702.reverseai` | Native crypto bridge `NativeAuthBridge._z05()` with AES-GCM + HMAC-SHA256 |

## Files

| File | Purpose |
|------|---------|
| `frida_hook_tartarus.js` | Frida hook for Tartarus — bypasses anti-tamper, hooks native JNI methods, captures curl traffic |
| `frida_hook_vitality.js` | Frida hook for Vitality — bypasses SSL pinning, hooks crypto operations and native bridge |
| `run_frida_extract.py` | Python runner — spawns APK, injects hooks, collects and saves output |
| `verify_keys.py` | Tests captured keys against `/auth` endpoint to identify real vs. decoy keys |

## Prerequisites

### 1. Android Emulator Setup
```bash
# Create an x86_64 API 30+ emulator
# Or use an existing rooted device
```

### 2. Frida Server on Device
```bash
# Download frida-server for your architecture
# Push and run:
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### 3. Install APKs
```bash
adb install "tartarus (1).apk"
adb install "vitality (1).apk"
```

### 4. Python Dependencies
```bash
pip install frida frida-tools requests
```

## Usage

### Quick Start — Extract Keys from Tartarus
```bash
python run_frida_extract.py tartarus --device emulator-5554 --timeout 45
```

### Quick Start — Extract Keys from Vitality
```bash
python run_frida_extract.py vitality --device emulator-5554 --timeout 45
```

### Verify Captured Keys
```bash
# Test all keys from latest tartarus results
python verify_keys.py --apk tartarus

# Test all keys from latest vitality results
python verify_keys.py --apk vitality

# Test a specific key
python verify_keys.py --keys "7a4212da71a964f8..."

# Test the known teambeta shared key
python verify_keys.py --test-teambeta

# Scan ALL log files for hex keys and test them
python verify_keys.py --all --apk tartarus --apk vitality
```

### Manual Frida Usage
```bash
# Direct Frida injection
frida -U -n "nz.ac.auckland.cs702.tartarus" -l frida_hook_tartarus.js
frida -U -n "nz.ac.auckland.se702.reverseai" -l frida_hook_vitality.js

# Spawn mode (bypasses anti-tamper that runs at startup)
frida -U -f nz.ac.auckland.cs702.tartarus -l frida_hook_tartarus.js --no-pause
```

## How It Works

### Tartarus Key Extraction Strategy

1. **Anti-tamper bypass**: `RuntimeProbe.inspectRuntime()` returns `false`; root detection via `File.exists()` for su/magisk paths returns `false`; debugger checks return `false`
2. **Anti-Frida bypass**: Hooks `libc.open()` to block `/proc/self/maps` reads; hooks `strstr()` to hide "frida" strings
3. **Direct JNI calls**: Calls `AssetProbe.probeEndpoint()` and `AssetProbe.probeGate()` to extract the endpoint URL and auth gate value
4. **curl interception**: Hooks `curl_easy_setopt` in `libtartarus_core.so` to capture CURLOPT_URL, CURLOPT_HTTPHEADER (Authorization), CURLOPT_POSTFIELDS
5. **JNI string capture**: Hooks `NewStringUTF` vtable entry to capture ALL strings returned from native code
6. **OkHttp interception**: Hooks `RequestBuilder` to capture Java-layer HTTP requests and headers

### Vitality Key Extraction Strategy

1. **Integrity bypass**: `X5.i()`, `G4.e()`, `F0.f()` all return `true` to pass integrity checks
2. **SSL pinning bypass**: Replaces `TrustManager` and `HostnameVerifier` to allow MITM
3. **Native bridge capture**: Hooks `NativeAuthBridge._z05()` which builds the auth token from install token + HMAC — captures both inputs and the returned token
4. **Crypto capture**: Hooks `SecretKeySpec`, `Cipher.init/doFinal`, `Mac.init/doFinal` to capture all key material
5. **Key blob extraction**: Hooks `X5.a()` (decrypt) and `X5.b()` (encrypt) to see the AES-GCM key blob
6. **SharedPreferences monitoring**: Captures `vkb` (encrypted key blob), `vit` (install token), `_p52` (HMAC blob)
7. **Native export enumeration**: Scans `libreverseai-crypto.so` exports for key/auth/derive functions and hooks them

### Distinguishing Real vs. Decoy Keys

The verification script POSTs to `https://ai.elliottwen.info/auth` with each captured key in the `Authorization: Bearer <key>` header:

- **Valid key**: HTTP 200 + JSON response with `signature` field → **REAL key**
- **Decoy key**: HTTP 401/403 or error response → **FAKE key**
- **Known shared key**: The teambeta key `7a4212da...` is accepted by the server for all APKs

## Known Results (from repo analysis)

### Vitality — Already Solved
The repo's analysis found that Vitality accepts the **teambeta shared key**:
```
7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7
```
The app's native code derives a per-call token via `NativeAuthBridge._z05()`, but the server also accepts this fixed key.

### Tartarus — Requires Dynamic Analysis
The API endpoint and gate value are entirely inside `libtartarus_core.so`. Static analysis cannot extract them. The Frida hook calls the JNI methods directly to extract the values at runtime.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `frida-server` not found | Ensure frida-server is running: `adb shell "su -c ps \| grep frida"` |
| App crashes on launch | The anti-tamper bypass may need adjustment; check hook output for errors |
| No keys captured | Try interacting with the app (tap "Generate" button) to trigger API calls |
| `DeviceNotFoundError` | Check `adb devices` output; use the correct device ID |
| SSL errors | The SSL bypass should handle this; if not, check TrustManager hook |
| `Java.perform` fails | The app may use a non-standard Java environment; try `Java.performNow` |
