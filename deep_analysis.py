import sys
import os
import struct
import zipfile
import re
import traceback

from androguard.misc import AnalyzeAPK
from androguard.core.dex import DEX

def extract_strings_from_so(so_data, min_len=8):
    """Extract printable strings from binary data."""
    strings = []
    current = b''
    for byte in so_data:
        if 32 <= byte < 127:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                strings.append(current.decode('ascii', errors='replace'))
            current = b''
    if len(current) >= min_len:
        strings.append(current.decode('ascii', errors='replace'))
    return strings

def analyze_apk_deep(apk_path, name):
    print(f"\n{'='*80}")
    print(f"  DEEP ANALYSIS: {name}")
    print(f"  Path: {apk_path}")
    print(f"{'='*80}")

    a, d, dx = AnalyzeAPK(apk_path)
    package = a.get_package()
    print(f"Package: {package}")

    # 1. ALL DEX strings - look for keys
    print(f"\n--- ALL DEX STRINGS (looking for keys) ---")
    hex_pattern = re.compile(r'^[0-9a-f]{32,128}$')
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]{24,}={0,2}$')
    key_strings = []

    for dex in d:
        for s in dex.get_strings():
            if len(s) >= 16:
                if hex_pattern.match(s):
                    print(f"  [HEX] {s}")
                    key_strings.append(('hex', s))
                elif b64_pattern.match(s) and len(s) >= 24:
                    print(f"  [B64] {s}")
                    key_strings.append(('b64', s))
                elif any(kw in s.lower() for kw in ['api', 'key', 'token', 'secret', 'bearer', 'auth', 'sk-', 'AKIA', 'AIza']):
                    if len(s) < 200:
                        print(f"  [KEYWORD] {s}")
                        key_strings.append(('keyword', s))

    # 2. Extract and analyze native libraries
    print(f"\n--- NATIVE LIBRARY STRINGS ---")
    with zipfile.ZipFile(apk_path, 'r') as zf:
        so_files = [f for f in zf.namelist() if f.endswith('.so') and 'arm64' in f]
        if not so_files:
            # fallback: try any .so files
            so_files = [f for f in zf.namelist() if f.endswith('.so')]
        print(f"  Found {len(so_files)} .so files")
        for so_file in so_files:
            print(f"\n  Analyzing: {so_file}")
            so_data = zf.read(so_file)
            strings = extract_strings_from_so(so_data, min_len=10)

            # Look for interesting strings
            found_any = False
            for s in strings:
                sl = s.lower()
                if any(kw in sl for kw in ['http', 'key', 'token', 'auth', 'bearer', 'sign', 'api',
                                            'encrypt', 'decrypt', 'cipher', 'aes', 'hmac', 'sha',
                                            'elliot', 'gate', 'endpoint', 'url', 'secret', 'credential',
                                            'probe', 'palette', 'warmup', 'route', 'password', 'base64']):
                    print(f"    [SO] {s[:200]}")
                    found_any = True

            # Look for hex strings in .so
            for s in strings:
                if hex_pattern.match(s) and len(s) >= 32:
                    print(f"    [SO_HEX] {s}")
                    found_any = True

            # Look for URLs
            for s in strings:
                if 'http' in s.lower() and ('.' in s) and len(s) < 300:
                    print(f"    [SO_URL] {s}")
                    found_any = True

            if not found_any:
                print(f"    (no interesting strings found)")

    # 3. Check assets
    print(f"\n--- ASSETS ---")
    with zipfile.ZipFile(apk_path, 'r') as zf:
        asset_files = [f for f in zf.namelist() if f.startswith('assets/') and not f.endswith('/')]
        print(f"  Found {len(asset_files)} asset files")
        for asset in asset_files[:50]:
            print(f"  {asset}")
            try:
                data = zf.read(asset)
                if len(data) < 1000:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        if any(kw in text.lower() for kw in ['key', 'token', 'secret', 'api', 'auth', 'http']):
                            print(f"    CONTENT: {text[:500]}")
                    except:
                        pass
                # Check if it's a binary with interesting strings
                if len(data) > 100:
                    asset_strings = extract_strings_from_so(data, min_len=12)
                    for s in asset_strings:
                        sl = s.lower()
                        if any(kw in sl for kw in ['key', 'token', 'secret', 'api', 'auth', 'http', 'bearer']):
                            print(f"    [ASSET_STR] {s[:200]}")
            except:
                pass

    # 4. Analyze fill-array-data for obfuscated keys
    print(f"\n--- FILL-ARRAY-DATA (potential obfuscated keys) ---")
    fill_array_count = 0
    for dex in d:
        for cls in dex.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code:
                    try:
                        bc = code.get_bc()
                        instructions = list(bc.get_instructions())
                        for inst in instructions:
                            if inst.get_name() == 'fill-array-data':
                                operands = inst.get_operands()
                                if len(operands) >= 2:
                                    data = operands[1][1]
                                    if isinstance(data, bytes) and len(data) >= 16:
                                        hex_str = data.hex()
                                        print(f"  {cls.get_name()}->{method.get_name()}: [{len(data)} bytes] {hex_str[:128]}{'...' if len(hex_str) > 128 else ''}")
                                        fill_array_count += 1
                    except Exception as e:
                        pass
    if fill_array_count == 0:
        print("  (no fill-array-data found)")

    # 5. Look for XOR decryption patterns
    print(f"\n--- XOR/ENCRYPT METHODS ---")
    xor_count = 0
    for dex in d:
        for cls in dex.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code:
                    try:
                        bc = code.get_bc()
                        instructions = list(bc.get_instructions())
                        has_xor = False
                        has_aget = False
                        has_const_string = False
                        strings_in_method = []

                        for inst in instructions:
                            name = inst.get_name()
                            if 'xor' in name:
                                has_xor = True
                            if 'aget' in name:
                                has_aget = True
                            if name == 'const-string' or name == 'const-string/jumbo':
                                operands = inst.get_operands()
                                if len(operands) >= 2:
                                    s = str(operands[1][1])
                                    strings_in_method.append(s)
                                    if len(s) > 5:
                                        has_const_string = True

                        if has_xor and (has_aget or has_const_string):
                            cls_name = cls.get_name()
                            meth_name = method.get_name()
                            if not cls_name.startswith('Landroid/') and not cls_name.startswith('Ljava/'):
                                print(f"  {cls_name}->{meth_name}")
                                if strings_in_method:
                                    for s in strings_in_method[:5]:
                                        print(f"    string: {s}")
                                xor_count += 1
                    except Exception as e:
                        pass
    if xor_count == 0:
        print("  (no XOR methods found)")

    # 6. Check SharedPreferences default values
    print(f"\n--- SHARED PREFERENCES / DEFAULT VALUES ---")
    for dex in d:
        for cls in dex.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code:
                    try:
                        bc = code.get_bc()
                        instructions = list(bc.get_instructions())
                        for inst in instructions:
                            name = inst.get_name()
                            if name == 'const-string' or name == 'const-string/jumbo':
                                operands = inst.get_operands()
                                if len(operands) >= 2:
                                    s = str(operands[1][1])
                                    if any(kw in s.lower() for kw in ['pref', 'default', 'config', 'setting']):
                                        print(f"  {cls.get_name()}->{method.get_name()}: {s[:200]}")
                    except:
                        pass

    # 7. Dump ALL long strings (potential keys/data)
    print(f"\n--- ALL LONG STRINGS (>= 32 chars) ---")
    long_strings = []
    for dex in d:
        for s in dex.get_strings():
            if len(s) >= 32:
                long_strings.append(s)
    # Print first 100
    for s in long_strings[:100]:
        print(f"  [{len(s)}] {s[:200]}")
    if len(long_strings) > 100:
        print(f"  ... and {len(long_strings) - 100} more")

    return key_strings

# Analyze both APKs
print("Starting deep analysis...")
print(f"Python version: {sys.version}")

try:
    tartarus_keys = analyze_apk_deep(r"C:\Users\zyzmc\Downloads\tartarus (1).apk", "TARTARUS")
except Exception as e:
    print(f"ERROR analyzing TARTARUS: {e}")
    traceback.print_exc()
    tartarus_keys = []

try:
    vitality_keys = analyze_apk_deep(r"C:\Users\zyzmc\Downloads\vitality (1).apk", "VITALITY")
except Exception as e:
    print(f"ERROR analyzing VITALITY: {e}")
    traceback.print_exc()
    vitality_keys = []

print(f"\n{'='*80}")
print(f"  SUMMARY")
print(f"{'='*80}")
print(f"Tartarus key candidates: {len(tartarus_keys)}")
for t, k in tartarus_keys:
    print(f"  [{t}] {k[:80]}")
print(f"Vitality key candidates: {len(vitality_keys)}")
for t, k in vitality_keys:
    print(f"  [{t}] {k[:80]}")
