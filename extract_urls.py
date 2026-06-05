import zipfile
import re

def extract_all_urls_and_endpoints(so_data):
    """Extract URLs, domains, and endpoint patterns from binary data."""
    results = []
    current = b''
    for byte in so_data:
        if 32 <= byte < 127:
            current += bytes([byte])
        else:
            if len(current) >= 8:
                s = current.decode('ascii', errors='replace')
                # Look for URLs
                if 'http' in s.lower() and '.' in s:
                    results.append(('URL', s))
                # Look for domain patterns
                elif re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', s):
                    if len(s) < 200:
                        results.append(('DOMAIN', s))
                # Look for API paths
                elif s.startswith('/') and len(s) > 5 and len(s) < 200:
                    if any(kw in s.lower() for kw in ['api', 'v1', 'v2', 'auth', 'token', 'key', 'endpoint', 'sign', 'verify', 'encrypt', 'decrypt', 'probe', 'warmup', 'palette', 'route', 'gate', 'elliot']):
                        results.append(('PATH', s))
                # Look for base64-like strings that could be keys
                elif re.match(r'^[A-Za-z0-9+/]{24,}={0,2}$', s) and len(s) >= 32:
                    results.append(('B64', s))
                # Look for hex strings
                elif re.match(r'^[0-9a-f]{32,128}$', s):
                    results.append(('HEX', s))
                # Look for bearer/auth tokens
                elif any(kw in s.lower() for kw in ['bearer', 'authorization', 'x-api-key', 'x-auth']):
                    results.append(('AUTH', s))
            current = b''
    return results

def extract_interesting_strings(so_data, min_len=6):
    """Extract strings with interesting keywords."""
    results = []
    current = b''
    for byte in so_data:
        if 32 <= byte < 127:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                s = current.decode('ascii', errors='replace')
                sl = s.lower()
                if any(kw in sl for kw in ['api', 'endpoint', 'url', 'host', 'server', 'gateway',
                                            'elliot', 'gate', 'probe', 'palette', 'warmup', 'route',
                                            'secret', 'credential', 'password', 'private',
                                            'token', 'bearer', 'authorization',
                                            'sign', 'verify', 'encrypt', 'decrypt',
                                            'aes', 'hmac', 'sha256', 'sha512',
                                            'curve25519', 'ed25519', 'x25519',
                                            'argon2', 'pbkdf', 'scrypt',
                                            'install', 'device', 'fingerprint',
                                            'canonical', 'tag', 'blob']):
                    if len(s) < 300:
                        results.append(s)
            current = b''
    return results

print("=" * 80)
print("  DETAILED URL/ENDPOINT/KEY EXTRACTION FROM NATIVE LIBS")
print("=" * 80)

# Analyze Tartarus
print("\n--- TARTARUS: libtartarus_core.so ---")
with zipfile.ZipFile(r"C:\Users\zyzmc\Downloads\tartarus (1).apk", 'r') as zf:
    so_data = zf.read("lib/arm64-v8a/libtartarus_core.so")
    urls = extract_all_urls_and_endpoints(so_data)
    print(f"\nURLs/Domains found: {len(urls)}")
    for typ, val in urls[:50]:
        if typ == 'URL':
            print(f"  [{typ}] {val[:200]}")

    # Also look for interesting strings
    interesting = extract_interesting_strings(so_data)
    print(f"\nInteresting strings: {len(interesting)}")
    seen = set()
    for s in interesting:
        if s not in seen:
            seen.add(s)
            print(f"  {s[:200]}")
    if len(interesting) > 50:
        print(f"  ... and {len(interesting) - 50} more")

# Analyze Vitality
print("\n--- VITALITY: libreverseai-core.so ---")
with zipfile.ZipFile(r"C:\Users\zyzmc\Downloads\vitality (1).apk", 'r') as zf:
    so_data = zf.read("lib/arm64-v8a/libreverseai-core.so")
    urls = extract_all_urls_and_endpoints(so_data)
    print(f"\nURLs/Domains found: {len(urls)}")
    for typ, val in urls[:50]:
        print(f"  [{typ}] {val[:200]}")

    interesting = extract_interesting_strings(so_data)
    print(f"\nInteresting strings: {len(interesting)}")
    seen = set()
    for s in interesting:
        if s not in seen:
            seen.add(s)
            print(f"  {s[:200]}")

print("\n--- VITALITY: libreverseai-crypto.so ---")
with zipfile.ZipFile(r"C:\Users\zyzmc\Downloads\vitality (1).apk", 'r') as zf:
    so_data = zf.read("lib/arm64-v8a/libreverseai-crypto.so")
    urls = extract_all_urls_and_endpoints(so_data)
    print(f"\nURLs/Domains found: {len(urls)}")
    for typ, val in urls[:50]:
        print(f"  [{typ}] {val[:200]}")

    interesting = extract_interesting_strings(so_data)
    print(f"\nInteresting strings: {len(interesting)}")
    seen = set()
    for s in interesting:
        if s not in seen:
            seen.add(s)
            print(f"  {s[:200]}")

    # Also look for ALL strings in the crypto lib (it's small)
    print(f"\n--- ALL strings from libreverseai-crypto.so (min len 4) ---")
    all_strings = []
    current = b''
    for byte in so_data:
        if 32 <= byte < 127:
            current += bytes([byte])
        else:
            if len(current) >= 4:
                all_strings.append(current.decode('ascii', errors='replace'))
            current = b''
    for s in all_strings:
        print(f"  {s}")
