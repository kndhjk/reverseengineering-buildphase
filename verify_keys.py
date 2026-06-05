#!/usr/bin/env python3
"""
API Key Verification Script
Tests extracted API keys against https://ai.elliottwen.info/auth
to distinguish real keys from decoy/fake keys.

Usage:
    python verify_keys.py                          # Test all keys from latest results
    python verify_keys.py --keys "key1" "key2"     # Test specific keys
    python verify_keys.py --results tartarus_results_20250605.json  # Test from file
    python verify_keys.py --test-teambeta           # Test the known teambeta key
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("[-] requests not installed. Run: pip install requests")
    print("[*] Trying urllib instead...")
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False
else:
    HAS_REQUESTS = True

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_URL = "https://ai.elliottwen.info/auth"
IMAGE_URL = "https://ai.elliottwen.info/generate_image"

# Known valid key from teambeta (shared server key accepted across APKs)
TEAMBETA_KEY = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7"


def test_key_requestlib(key, timeout=15):
    """Test a key using the requests library."""
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(AUTH_URL, headers=headers, json={}, timeout=timeout)
        status = resp.status_code
        body = resp.text[:500]
        try:
            json_body = resp.json()
        except Exception:
            json_body = None
        return status, body, json_body
    except requests.exceptions.Timeout:
        return -1, "TIMEOUT", None
    except requests.exceptions.ConnectionError as e:
        return -2, f"CONNECTION_ERROR: {e}", None
    except Exception as e:
        return -3, f"ERROR: {e}", None


def test_key_urllib(key, timeout=15):
    """Test a key using urllib (fallback)."""
    import json as json_mod

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(AUTH_URL, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")[:500]
            try:
                json_body = json_mod.loads(body)
            except Exception:
                json_body = None
            return status, body, json_body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        try:
            json_body = json_mod.loads(body)
        except Exception:
            json_body = None
        return e.code, body, json_body
    except urllib.error.URLError as e:
        return -2, f"URL_ERROR: {e}", None
    except Exception as e:
        return -3, f"ERROR: {e}", None


def test_key(key, timeout=15):
    """Test a key against the auth endpoint."""
    if HAS_REQUESTS:
        return test_key_requestlib(key, timeout)
    else:
        return test_key_urllib(key, timeout)


def format_key(key, max_len=60):
    """Format a key for display."""
    if len(key) <= max_len:
        return key
    return f"{key[:30]}...{key[-30:]}"


def load_results_file(filepath):
    """Load keys from a results JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    keys = []
    if "api_keys" in data:
        for k in data["api_keys"]:
            if isinstance(k, dict):
                keys.append(k.get("value", ""))
            else:
                keys.append(str(k))
    if "auth_headers" in data:
        for h in data["auth_headers"]:
            # Extract token from "Authorization: Bearer <token>" or "Bearer <token>"
            match = re.search(r"(?:Bearer\s+)?([a-f0-9]{40,})", h)
            if match:
                keys.append(match.group(1))
    if "native_strings" in data:
        for s in data["native_strings"]:
            # Look for hex strings that could be keys
            if re.match(r"^[a-f0-9]{40,}$", s):
                keys.append(s)

    return list(set(keys))


def find_latest_results(apk_name):
    """Find the most recent results file for the given APK."""
    files = []
    for f in os.listdir(SCRIPT_DIR):
        if f.startswith(f"{apk_name}_results_") and f.endswith(".json"):
            files.append(os.path.join(SCRIPT_DIR, f))
    if files:
        return max(files, key=os.path.getmtime)
    return None


def main():
    parser = argparse.ArgumentParser(description="API Key Verification")
    parser.add_argument("--keys", nargs="+", help="Keys to test directly")
    parser.add_argument("--results", help="Path to results JSON file")
    parser.add_argument("--apk", choices=["tartarus", "vitality"], help="APK name to find latest results")
    parser.add_argument("--test-teambeta", action="store_true", help="Test the known teambeta key")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15s)")
    parser.add_argument("--all", action="store_true", help="Test all found keys including from latest logs")
    args = parser.parse_args()

    keys_to_test = []

    # Add teambeta key if requested
    if args.test_teambeta:
        keys_to_test.append(("teambeta_known", TEAMBETA_KEY))

    # Add directly specified keys
    if args.keys:
        for k in args.keys:
            keys_to_test.append(("manual", k))

    # Load from results file
    if args.results:
        if os.path.exists(args.results):
            keys = load_results_file(args.results)
            for k in keys:
                keys_to_test.append((f"file:{os.path.basename(args.results)}", k))
        else:
            print(f"[-] Results file not found: {args.results}")

    # Find latest results for APK
    if args.apk:
        results_file = find_latest_results(args.apk)
        if results_file:
            print(f"[*] Loading results from: {results_file}")
            keys = load_results_file(results_file)
            for k in keys:
                keys_to_test.append((f"{args.apk}:latest", k))
        else:
            print(f"[-] No results files found for {args.apk}")

    # If --all, also scan all log files for hex keys
    if args.all:
        for f in os.listdir(SCRIPT_DIR):
            if f.endswith(".txt") and ("tartarus" in f or "vitality" in f):
                filepath = os.path.join(SCRIPT_DIR, f)
                try:
                    with open(filepath, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    # Find hex strings that look like API keys (64+ hex chars)
                    hex_keys = re.findall(r"[a-f0-9]{64,128}", content)
                    for k in hex_keys:
                        keys_to_test.append((f"log:{f}", k))
                except Exception:
                    pass

    if not keys_to_test:
        print("[!] No keys to test. Options:")
        print("  --test-teambeta              Test the known teambeta key")
        print("  --keys <key1> <key2>         Test specific keys")
        print("  --results <file.json>        Load from results file")
        print("  --apk tartarus|vitality      Load from latest results")
        print("  --all                        Scan all log files for hex keys")
        return

    # Deduplicate
    seen = set()
    unique_keys = []
    for source, key in keys_to_test:
        if key not in seen:
            seen.add(key)
            unique_keys.append((source, key))

    print(f"\n{'='*70}")
    print(f"  API Key Verification")
    print(f"  Endpoint: {AUTH_URL}")
    print(f"  Keys to test: {len(unique_keys)}")
    print(f"{'='*70}\n")

    results = []
    valid_keys = []
    decoy_keys = []

    for i, (source, key) in enumerate(unique_keys):
        print(f"[{i+1}/{len(unique_keys)}] Testing key from {source}:")
        print(f"  Key: {format_key(key)}")

        status, body, json_body = test_key(key, timeout=args.timeout)

        if status == 200:
            signature = None
            if json_body:
                signature = json_body.get("signature", json_body.get("token", None))
            result = {
                "status": "VALID",
                "key": key,
                "source": source,
                "http_status": status,
                "signature": signature,
                "response": body[:200],
            }
            valid_keys.append(result)
            print(f"  ✅ VALID (HTTP {status})")
            if signature:
                print(f"  Signature: {signature[:80]}{'...' if len(str(signature)) > 80 else ''}")
            print(f"  Response: {body[:200]}")
        elif status > 0:
            result = {
                "status": "INVALID",
                "key": key,
                "source": source,
                "http_status": status,
                "response": body[:200],
            }
            decoy_keys.append(result)
            print(f"  ❌ INVALID (HTTP {status})")
            print(f"  Response: {body[:200]}")
        else:
            result = {
                "status": "ERROR",
                "key": key,
                "source": source,
                "error": body,
            }
            print(f"  ⚠️  ERROR: {body}")
            results.append(result)

        results.append(result)
        time.sleep(0.5)  # Rate limit

    # Summary
    print(f"\n{'='*70}")
    print(f"  VERIFICATION SUMMARY")
    print(f"{'='*70}")
    print(f"  Total tested:  {len(unique_keys)}")
    print(f"  Valid keys:    {len(valid_keys)}")
    print(f"  Decoy keys:    {len(decoy_keys)}")
    print(f"  Errors:        {len([r for r in results if r['status'] == 'ERROR'])}")

    if valid_keys:
        print(f"\n{'='*70}")
        print(f"  ✅ REAL API KEYS (passed /auth verification)")
        print(f"{'='*70}")
        for vk in valid_keys:
            print(f"\n  Source: {vk['source']}")
            print(f"  Key:    {vk['key']}")
            if vk.get("signature"):
                print(f"  Sig:    {vk['signature']}")

    if decoy_keys:
        print(f"\n{'='*70}")
        print(f"  ❌ DECOY/FAKE KEYS (failed /auth verification)")
        print(f"{'='*70}")
        for dk in decoy_keys:
            print(f"\n  Source: {dk['source']}")
            print(f"  Key:    {format_key(dk['key'])}")
            print(f"  Status: HTTP {dk['http_status']}")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(SCRIPT_DIR, f"verification_results_{timestamp}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "auth_url": AUTH_URL,
            "total_tested": len(unique_keys),
            "valid_keys": valid_keys,
            "decoy_keys": decoy_keys,
            "all_results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Full results saved: {output_file}")


if __name__ == "__main__":
    main()
