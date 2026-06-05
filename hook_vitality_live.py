#!/usr/bin/env python3
"""Hook vitality APK to extract the independent API key."""
import frida
import time
import sys

device = frida.get_device('emulator-5554', timeout=5)
print(f'[*] Device: {device.name}')

procs = device.enumerate_processes()
vitality = None
for p in procs:
    if 'reverseai' in p.name.lower() or 'vitality' in p.name.lower():
        vitality = p
        break

if not vitality:
    print('[-] Vitality not running')
    sys.exit(1)

print(f'[*] Found: {vitality.name} (PID: {vitality.pid})')
session = device.attach(vitality.pid)
print(f'[*] Attached')

JS = r'''
"use strict";

var captured = [];

function log(tag, msg) {
    console.log("[" + tag + "] " + msg);
    send({type: "capture", tag: tag, data: msg});
}

Java.perform(function() {
    log("INIT", "Hooks loading...");

    // 1. Hook NativeAuthBridge._z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            log("AUTH_KEY", "_z05 returned: " + result);
            captured.push({tag: "AUTH_KEY", value: result});
            return result;
        };
        log("HOOK", "_z05 hooked");
    } catch(e) { log("ERR", "_z05: " + e); }

    // 2. Hook X5.f() - key blob
    try {
        var X5 = Java.use("X5");
        X5.f.implementation = function() {
            var r = this.f();
            var hex = "";
            for (var i = 0; i < r.length; i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            log("KEY_BLOB", "X5.f() = " + hex);
            return r;
        };
        log("HOOK", "X5.f hooked");
    } catch(e) { log("ERR", "X5.f: " + e); }

    // 3. Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            log("CRYPTO_KEY", "SecretKeySpec algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            return this.$init(bytes, algo);
        };
        log("HOOK", "SecretKeySpec hooked");
    } catch(e) { log("ERR", "SecretKeySpec: " + e); }

    // 4. Hook Cipher.init
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    log("CIPHER_KEY", "Cipher.init mode=" + mode + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
        };
        log("HOOK", "Cipher.init hooked");
    } catch(e) { log("ERR", "Cipher: " + e); }

    // 5. Hook OkHttp Authorization header
    try {
        var RB = Java.use("okhttp3.Request$Builder");
        RB.addHeader.overload("java.lang.String", "java.lang.String").implementation = function(name, value) {
            if (name.toLowerCase() === "authorization") {
                log("AUTH_HEADER", "Authorization: " + value);
                captured.push({tag: "AUTH_HEADER", value: value});
            }
            return this.addHeader(name, value);
        };
        log("HOOK", "addHeader hooked");
    } catch(e) { log("ERR", "addHeader: " + e); }

    // 6. Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            if (key === "vkb" || key === "vit" || key === "_p52") {
                log("SP", "getString(" + key + ") = " + (val ? val.substring(0, 100) : "null"));
            }
            return val;
        };
        log("HOOK", "SP hooked");
    } catch(e) { log("ERR", "SP: " + e); }

    // 7. Bypass integrity checks
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        log("HOOK", "Integrity bypassed");
    } catch(e) { log("ERR", "Integrity: " + e); }

    // 8. Bypass Debug
    try {
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
        log("HOOK", "Debug bypassed");
    } catch(e) {}

    log("INIT", "All hooks installed. Calling _z05 directly...");

    // Direct call to _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        var token = NAB._y01();
        var t = NAB._y02();
        var hmac = NAB._y03();

        var th = "";
        if (token) for (var i = 0; i < Math.min(token.length, 32); i++) th += ("0" + (token[i] & 0xFF).toString(16)).slice(-2);
        var hh = "";
        if (hmac) for (var i = 0; i < Math.min(hmac.length, 32); i++) hh += ("0" + (hmac[i] & 0xFF).toString(16)).slice(-2);

        log("INPUTS", "_y01 token: " + th + " (len=" + (token ? token.length : 0) + ")");
        log("INPUTS", "_y02 time: " + t);
        log("INPUTS", "_y03 hmac: " + hh + " (len=" + (hmac ? hmac.length : 0) + ")");

        // Convert long to byte array
        var tb = new java.lang.Long(t);
        var timeBytes = java.nio.ByteBuffer.allocate(8).putLong(t).array();

        var key = NAB._z05(token, timeBytes, hmac);
        log("DIRECT_KEY", "_z05 returned: " + key);
        captured.push({tag: "DIRECT_KEY", value: key});
    } catch(e) { log("ERR", "Direct call: " + e); }
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
        print(f'[ERR] {msg.get("description", "")}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()

print('[*] Waiting 10s for hooks...')
time.sleep(10)

print('\n=== CAPTURED VALUES ===')
for c in captured:
    tag = c.get('tag', '')
    val = c.get('value', c.get('data', ''))
    if tag in ('AUTH_KEY', 'DIRECT_KEY', 'AUTH_HEADER', 'KEY_BLOB', 'CRYPTO_KEY', 'CIPHER_KEY'):
        print(f'  {tag}: {val}')

session.detach()
print('[*] Done')
