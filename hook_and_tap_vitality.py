#!/usr/bin/env python3
"""Hook vitality and tap GENERATE button to trigger auth."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"

device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')
print(f'[*] Attached to Vitality AI')

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
            console.log("[_z05] RETURNED: " + result);
            keys.push(result);
            // Log inputs
            if (a) {
                var h = "";
                for (var i = 0; i < a.length; i++) h += ("0" + (a[i] & 0xFF).toString(16)).slice(-2);
                console.log("[_z05] input_token: " + h);
            }
            return result;
        };
        console.log("[HOOK] _z05");
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook class v
    try {
        var v_cls = Java.use("v");
        v_cls.d.implementation = function() {
            var r = this.d();
            console.log("[v.d] " + (r ? r : "null"));
            return r;
        };
        v_cls.e.implementation = function() {
            var r = this.e();
            console.log("[v.e] " + (r ? r : "null"));
            return r;
        };
        console.log("[HOOK] class v");
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Bypass
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}

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

    console.log("[INIT] Hooks ready. Keys will be captured when _z05 is called.");
});
'''

captured_keys = []
def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = str(msg.get('payload', ''))
        print(payload)
        if 'RETURNED:' in payload:
            key = payload.split('RETURNED: ')[1].strip()
            captured_keys.append(key)
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()

time.sleep(2)

# Type a prompt in the text field first
print('[*] Typing prompt...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '540', '291'], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'text', 'cat'], timeout=5)
time.sleep(0.5)

# Tap GENERATE button (center of [55,382][378,514] = 216, 448)
print('[*] Tapping GENERATE button...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '216', '448'], timeout=5)

print('[*] Waiting 20s for auth flow...')
time.sleep(20)

print('\n=== CAPTURED KEYS ===')
for k in captured_keys:
    print(f'  KEY: {k}')

if not captured_keys:
    print('  No keys captured')

session.detach()
print('[*] Done')
