#!/usr/bin/env python3
"""
Frida API Key Extraction Runner
Spawns the target APK, injects hooks, captures keys and auth headers.

Usage:
    python run_frida_extract.py tartarus [--device emulator-5554] [--timeout 45]
    python run_frida_extract.py vitality [--device emulator-5554] [--timeout 45]

Requirements:
    - Android emulator or rooted device with frida-server running
    - APK installed on the device
    - frida Python package installed
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

try:
    import frida
except ImportError:
    print("[-] Frida not installed. Run: pip install frida frida-tools")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# APK configurations
APK_CONFIG = {
    "tartarus": {
        "package": "nz.ac.auckland.cs702.tartarus",
        "activity": "com.example.playground.MainActivity",
        "hook_script": os.path.join(SCRIPT_DIR, "frida_hook_tartarus.js"),
    },
    "vitality": {
        "package": "nz.ac.auckland.se702.reverseai",
        "activity": "nz.ac.auckland.se702.reverseai.MainActivity",
        "hook_script": os.path.join(SCRIPT_DIR, "frida_hook_vitality.js"),
    },
}


def find_adb():
    """Find adb executable."""
    candidates = [
        r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe",
        "adb",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    # Try PATH
    try:
        result = subprocess.run(["where", "adb"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "adb"


ADB = find_adb()


def run_adb(device_id, *args):
    """Run an adb command."""
    cmd = [ADB, "-s", device_id] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result


def ensure_installed(device_id, package, apk_path=None):
    """Ensure the APK is installed on the device."""
    result = run_adb(device_id, "shell", "pm", "path", package)
    if result.returncode == 0 and result.stdout.strip():
        print(f"[*] Package already installed: {package}")
        return True

    if apk_path and os.path.exists(apk_path):
        print(f"[*] Installing {apk_path}...")
        result = run_adb(device_id, "install", "-r", apk_path)
        if result.returncode == 0:
            print(f"[+] Installed successfully")
            return True
        else:
            print(f"[-] Install failed: {result.stderr}")
            return False

    print(f"[-] Package {package} not found on device. Install it manually.")
    return False


def get_device(device_id):
    """Get the Frida device."""
    try:
        device = frida.get_device(device_id, timeout=10)
        print(f"[*] Device: {device.name} (type: {device.type})")
        return device
    except Exception as e:
        print(f"[-] Failed to get device '{device_id}': {e}")
        print("[!] Make sure the emulator is running and frida-server is active")
        return None


def spawn_and_hook(device, config, timeout=45):
    """Spawn the app and inject the Frida hook."""
    package = config["package"]
    hook_script_path = config["hook_script"]

    if not os.path.exists(hook_script_path):
        print(f"[-] Hook script not found: {hook_script_path}")
        return None

    with open(hook_script_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # Force stop the app first
    print(f"[*] Force-stopping {package}...")
    try:
        run_adb(device.id, "shell", "am", "force-stop", package)
    except Exception:
        pass
    time.sleep(1)

    # Spawn the app
    print(f"[*] Spawning {package}...")
    try:
        pid = device.spawn([package])
        print(f"[*] Spawned PID: {pid}")
    except Exception as e:
        print(f"[-] Spawn failed: {e}")
        # Try attaching to running process instead
        try:
            for proc in device.enumerate_processes():
                if package in proc.name or package.split(".")[-1] in proc.name:
                    print(f"[*] Found running process: {proc.name} (PID: {proc.pid})")
                    pid = proc.pid
                    break
            else:
                print(f"[-] Process not found for {package}")
                return None
        except Exception as e2:
            print(f"[-] Process enumeration failed: {e2}")
            return None

    # Attach and inject
    try:
        session = device.attach(pid)
        print(f"[*] Attached to PID {pid}")
    except Exception as e:
        print(f"[-] Attach failed: {e}")
        return None

    captured_messages = []

    def on_message(msg, data):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if msg.get("type") == "send":
            payload = msg.get("payload", "")
            if isinstance(payload, dict):
                tag = payload.get("tag", "unknown")
                data_str = payload.get("data", "")
                line = f"[{ts}] [{tag}] {data_str}"
            else:
                line = f"[{ts}] {payload}"
            print(line)
            captured_messages.append({"timestamp": ts, "raw": payload, "line": line})
        elif msg.get("type") == "error":
            desc = msg.get("description", str(msg))
            line = f"[{ts}] [ERROR] {desc}"
            print(line)
            captured_messages.append({"timestamp": ts, "type": "error", "line": line})

    try:
        script = session.create_script(js_code, runtime="v8")
        script.on("message", on_message)
        script.load()
        print(f"[*] Hook script loaded")
    except Exception as e:
        print(f"[-] Script load failed: {e}")
        return None

    # Resume the app
    try:
        device.resume(pid)
        print(f"[*] App resumed")
    except Exception:
        pass

    # Wait for hooks to capture data
    print(f"\n[*] Waiting {timeout}s for hooks to capture data...")
    print("[*] You can interact with the app on the emulator to trigger API calls")
    print("[*] Press Ctrl+C to stop early\n")

    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")

    # Detach
    try:
        session.detach()
        print("[*] Session detached")
    except Exception:
        pass

    return captured_messages


def parse_captured_keys(messages):
    """Parse captured messages to extract API keys and auth headers."""
    results = {
        "api_keys": [],
        "auth_headers": [],
        "urls": [],
        "native_strings": [],
        "all_captures": [],
    }

    seen_keys = set()
    seen_headers = set()

    for msg in messages:
        raw = msg.get("raw", "")
        line = msg.get("line", "")

        if isinstance(raw, dict):
            tag = raw.get("tag", "")
            data = raw.get("data", "")

            if tag == "KEY_FOUND" or tag == "AUTH_TOKEN":
                # Extract the value from quotes
                match = re.search(r'=\s*"(.+)"', data)
                if match:
                    val = match.group(1)
                    if val not in seen_keys and len(val) > 5:
                        seen_keys.add(val)
                        results["api_keys"].append({"source": data.split("=")[0].strip(), "value": val})

            elif tag == "AUTH_HEADER":
                if data not in seen_headers:
                    seen_headers.add(data)
                    results["auth_headers"].append(data)

            elif tag == "HTTP" and "URL:" in data:
                url = data.split("URL:", 1)[1].strip()
                results["urls"].append(url)

            elif tag == "CURL" and "URL:" in data:
                url = data.split("URL:", 1)[1].strip()
                results["urls"].append(url)

            elif tag == "NATIVE_STR" or tag == "JNI_OUT":
                match = re.search(r'"(.+)"', data)
                if match:
                    val = match.group(1)
                    if val not in seen_keys and len(val) > 10:
                        seen_keys.add(val)
                        results["native_strings"].append(val)

            elif tag == "SP":
                match = re.search(r'putString\("(.+?)"\)\s*=\s*"(.+?)"', data)
                if match:
                    key, val = match.group(1), match.group(2)
                    if val not in seen_keys and len(val) > 10:
                        seen_keys.add(val)
                        results["api_keys"].append({"source": f"SP:{key}", "value": val})

            elif tag == "CURL" and "HEADER:" in data:
                hdr = data.split("HEADER:", 1)[1].strip()
                if "authorization" in hdr.lower() and hdr not in seen_headers:
                    seen_headers.add(hdr)
                    results["auth_headers"].append(hdr)

    return results


def save_results(apk_name, messages, parsed):
    """Save results to files."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save raw log
    log_file = os.path.join(SCRIPT_DIR, f"{apk_name}_log_{timestamp}.txt")
    with open(log_file, "w", encoding="utf-8") as f:
        for msg in messages:
            f.write(msg.get("line", str(msg)) + "\n")
    print(f"[+] Raw log saved: {log_file}")

    # Save parsed results
    results_file = os.path.join(SCRIPT_DIR, f"{apk_name}_results_{timestamp}.json")
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)
    print(f"[+] Results saved: {results_file}")

    return log_file, results_file


def main():
    parser = argparse.ArgumentParser(description="Frida API Key Extraction Runner")
    parser.add_argument("apk", choices=["tartarus", "vitality"], help="Target APK")
    parser.add_argument("--device", default="emulator-5554", help="Device ID (default: emulator-5554)")
    parser.add_argument("--timeout", type=int, default=45, help="Capture timeout in seconds (default: 45)")
    parser.add_argument("--apk-path", help="Path to APK file for installation")
    args = parser.parse_args()

    config = APK_CONFIG[args.apk]
    print(f"{'='*60}")
    print(f"  Frida API Key Extraction: {args.apk.upper()}")
    print(f"  Package: {config['package']}")
    print(f"  Device: {args.device}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{'='*60}\n")

    # Get device
    device = get_device(args.device)
    if not device:
        print("\n[!] Setup instructions:")
        print("  1. Start Android emulator: emulator -avd <name>")
        print("  2. Push frida-server: adb push frida-server /data/local/tmp/")
        print("  3. Run frida-server: adb shell 'su -c /data/local/tmp/frida-server &'")
        print("  4. Install APK: adb install <apk_file>")
        return

    # Ensure APK is installed
    if args.apk_path:
        if not ensure_installed(args.device, config["package"], args.apk_path):
            return

    # Spawn and hook
    messages = spawn_and_hook(device, config, timeout=args.timeout)
    if not messages:
        print("[-] No messages captured")
        return

    # Parse results
    parsed = parse_captured_keys(messages)

    # Display summary
    print(f"\n{'='*60}")
    print(f"  EXTRACTION RESULTS: {args.apk.upper()}")
    print(f"{'='*60}")

    if parsed["api_keys"]:
        print(f"\n[+] API Keys / Tokens found ({len(parsed['api_keys'])}):")
        for i, k in enumerate(parsed["api_keys"]):
            print(f"  [{i+1}] Source: {k['source']}")
            print(f"      Value:  {k['value'][:80]}{'...' if len(k['value']) > 80 else ''}")
    else:
        print("\n[-] No API keys captured")

    if parsed["auth_headers"]:
        print(f"\n[+] Authorization headers found ({len(parsed['auth_headers'])}):")
        for i, h in enumerate(parsed["auth_headers"]):
            print(f"  [{i+1}] {h[:100]}{'...' if len(h) > 100 else ''}")
    else:
        print("\n[-] No Authorization headers captured")

    if parsed["urls"]:
        print(f"\n[+] URLs found ({len(parsed['urls'])}):")
        seen = set()
        for u in parsed["urls"]:
            if u not in seen:
                seen.add(u)
                print(f"  - {u}")

    if parsed["native_strings"]:
        print(f"\n[+] Interesting native strings ({len(parsed['native_strings'])}):")
        for s in parsed["native_strings"][:20]:
            print(f"  - {s[:120]}{'...' if len(s) > 120 else ''}")

    # Save results
    log_file, results_file = save_results(args.apk, messages, parsed)

    print(f"\n{'='*60}")
    print(f"  Done! Run verify_keys.py to test captured keys against the API")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
