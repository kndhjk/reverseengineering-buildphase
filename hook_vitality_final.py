#!/usr/bin/env python3
"""Hook vitality - call _z05 directly and hook class v methods."""
import frida
import time
import sys
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"

device = frida.get_device('emulator-5554', timeout=5)
print(f'[*] Device: {device.name}')

subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'am', 'force-stop', PACKAGE], timeout=10)
time.sleep(1)

pid = device.spawn([PACKAGE])
print(f'[*] Spawned PID: {pid}')
session = device.attach(pid)

JS = r'''
"use strict";

function hexEncode(arr, max) {
    max = max || arr.length;
    var h = "";
    for (var i = 0; i < Math.min(arr.length, max); i++) h += ("0" + (arr[i] & 0xFF).toString(16)).slice(-2);
    return h;
}

function log(tag, msg) {
    console.log("[" + tag + "] " + msg);
    send({type: "capture", tag: tag, data: msg});
}

Java.perform(function() {
    log("INIT", "Loading hooks...");

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            log("AUTH_KEY", "API KEY: " + result);
            if (a) log("INPUT", "token: " + hexEncode(a, 64));
            if (b) log("INPUT", "time: " + hexEncode(b, 16));
            if (c) log("INPUT", "hmac: " + hexEncode(c, 16));
            return result;
        };
        log("HOOK", "_z05 hooked");
    } catch(e) { log("ERR", "_z05: " + e); }

    // Hook class v methods (API client)
    try {
        var v_cls = Java.use("v");
        // Hook all methods
        v_cls.d.implementation = function() {
            var r = this.d();
            log("V_D", "v.d() = " + (r ? r.substring(0, 200) : "null"));
            return r;
        };
        v_cls.e.implementation = function() {
            var r = this.e();
            log("V_E", "v.e() = " + (r ? r.substring(0, 200) : "null"));
            return r;
        };
        log("HOOK", "class v hooked");
    } catch(e) { log("ERR", "class v: " + e); }

    // Hook X5
    try {
        var X5 = Java.use("X5");
        X5.f.implementation = function() {
            var r = this.f();
            log("KEY_BLOB", "X5.f() = " + hexEncode(r, 64) + " (len=" + r.length + ")");
            return r;
        };
        log("HOOK", "X5.f hooked");
    } catch(e) {}

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            log("SECRET_KEY", "algo=" + algo + " len=" + bytes.length + " hex=" + hexEncode(bytes, 64));
            return this.$init(bytes, algo);
        };
        log("HOOK", "SKS hooked");
    } catch(e) {}

    // Bypass integrity
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
        log("HOOK", "Bypass OK");
    } catch(e) {}

    log("INIT", "Hooks ready. Calling _z05 directly...");

    // Direct call to _z05 with proper byte conversion
    Java.choose("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge", {
        onMatch: function(instance) {
            log("FIND", "Found NativeAuthBridge instance");
        },
        onComplete: function() {}
    });

    // Get the static methods
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        var token = NAB._y01();
        var t = NAB._y02();
        var hmac = NAB._y03();

        log("DATA", "token: " + hexEncode(token, 64) + " len=" + (token ? token.length : 0));
        log("DATA", "time: " + t);
        log("DATA", "hmac: " + hexEncode(hmac, 16) + " len=" + (hmac ? hmac.length : 0));

        // Convert long to byte array manually (big-endian)
        var timeBytes = Java.array("byte", [
            (t >> 56) & 0xFF, (t >> 48) & 0xFF, (t >> 40) & 0xFF, (t >> 32) & 0xFF,
            (t >> 24) & 0xFF, (t >> 16) & 0xFF, (t >> 8) & 0xFF, t & 0xFF
        ]);

        var key = NAB._z05(token, timeBytes, hmac);
        log("DIRECT_KEY", "API KEY: " + key);
    } catch(e) { log("ERR", "Direct call: " + e); }

    // Also try calling with null/empty inputs to see what happens
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        var emptyArr = Java.array("byte", []);
        var key2 = NAB._z05(emptyArr, emptyArr, emptyArr);
        log("EMPTY_KEY", "_z05 with empty: " + key2);
    } catch(e) { log("ERR", "Empty call: " + e); }

    log("INIT", "Waiting for app to trigger auth...");
});
'''

captured = []
def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = msg.get('payload', {})
        if isinstance(payload, dict):
            tag = payload.get('tag', '')
            info = payload.get('data', '')
            print(f'[{tag}] {info}')
            captured.append(payload)
        else:
            print(f'[MSG] {payload}')
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()

device.resume(pid)
print(f'[*] App resumed. Waiting 25s...')
time.sleep(25)

print('\n=== RESULTS ===')
for c in captured:
    tag = c.get('tag', '')
    val = c.get('value', c.get('data', ''))
    if 'KEY' in tag or 'AUTH' in tag or 'DIRECT' in tag:
        print(f'  >>> {tag}: {val}')

session.detach()
print('[*] Done')
