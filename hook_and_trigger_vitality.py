#!/usr/bin/env python3
"""Hook vitality and auto-trigger auth via adb tap."""
import frida
import time
import sys
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"

device = frida.get_device('emulator-5554', timeout=5)

# Don't respawn - attach to existing process
procs = device.enumerate_processes()
vitality = None
for p in procs:
    if 'reverseai' in p.name.lower() or 'vitality' in p.name.lower():
        vitality = p
        break

if vitality:
    print(f'[*] Attaching to existing: {vitality.name} (PID: {vitality.pid})')
    session = device.attach(vitality.pid)
else:
    subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'am', 'force-stop', PACKAGE], timeout=10)
    time.sleep(1)
    pid = device.spawn([PACKAGE])
    print(f'[*] Spawned PID: {pid}')
    session = device.attach(pid)
    device.resume(pid)
    time.sleep(3)

JS = r'''
"use strict";

var keys = [];

Java.perform(function() {
    console.log("[INIT] Hooks loading...");

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] KEY: " + result);
            keys.push(result);
            return result;
        };
        console.log("[HOOK] _z05");
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook all String methods in class v
    try {
        var v_cls = Java.use("v");
        v_cls.d.implementation = function() {
            var r = this.d();
            console.log("[v.d] " + (r ? r.substring(0, 200) : "null"));
            return r;
        };
        v_cls.e.implementation = function() {
            var r = this.e();
            console.log("[v.e] " + (r ? r.substring(0, 200) : "null"));
            return r;
        };
        console.log("[HOOK] class v");
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            if (key === "vkb" || key === "vit" || key === "_p52") {
                console.log("[SP] " + key + " = " + (val ? val : "null"));
            }
            return val;
        };
        console.log("[HOOK] SP");
    } catch(e) { console.log("[ERR] SP: " + e); }

    // Bypass integrity
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
        console.log("[HOOK] Bypass OK");
    } catch(e) {}

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            console.log("[SKS] algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            return this.$init(bytes, algo);
        };
        console.log("[HOOK] SKS");
    } catch(e) {}

    console.log("[INIT] All hooks installed. Ready for auth flow.");
});
'''

captured_keys = []
def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = str(msg.get('payload', ''))
        print(f'[MSG] {payload}')
        if 'KEY:' in payload:
            key = payload.split('KEY: ')[1].strip() if 'KEY: ' in payload else ''
            if key:
                captured_keys.append(key)
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()

time.sleep(2)

# Auto-tap the Generate button using adb
# First, find the button coordinates
print('[*] Tapping Generate button via adb...')
# Get screen size
result = subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'wm', 'size'], capture_output=True, text=True)
print(f'  Screen: {result.stdout.strip()}')

# Use uiautomator to find the Generate button
result = subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'uiautomator', 'dump', '/dev/tty'],
                       capture_output=True, text=True, timeout=15)
# Look for Generate button
if 'Generate' in result.stdout:
    import re
    # Find bounds of Generate button
    match = re.search(r'text="Generate"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', result.stdout)
    if match:
        x1, y1, x2, y2 = int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        print(f'  Generate button at ({cx}, {cy})')
        subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', str(cx), str(cy)], timeout=10)
        print('[*] Tapped Generate button!')
    else:
        print('[*] Could not find button bounds, trying center of screen')
        subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '540', '1200'], timeout=10)
else:
    print('[*] Generate button not found in UI dump, trying adb shell input')
    # Try common button positions
    subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '540', '1200'], timeout=10)

print('[*] Waiting 15s for auth flow...')
time.sleep(15)

print('\n=== CAPTURED KEYS ===')
for k in captured_keys:
    print(f'  {k}')

if not captured_keys:
    print('  No keys captured from _z05 hook')

session.detach()
print('[*] Done')
