#!/usr/bin/env python3
"""Hook vitality APK - spawn mode to catch all key generation."""
import frida
import time
import sys
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"

device = frida.get_device('emulator-5554', timeout=5)
print(f'[*] Device: {device.name}')

# Force stop and respawn
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'am', 'force-stop', PACKAGE], timeout=10)
time.sleep(1)

# Spawn the app
print(f'[*] Spawning {PACKAGE}...')
pid = device.spawn([PACKAGE])
print(f'[*] Spawned PID: {pid}')

session = device.attach(pid)
print(f'[*] Attached')

JS = r'''
"use strict";

function log(tag, msg) {
    console.log("[" + tag + "] " + msg);
    send({type: "capture", tag: tag, data: msg});
}

Java.perform(function() {
    log("INIT", "Hooks loading...");

    // Hook _z05 BEFORE it's called
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            log("AUTH_KEY", "_z05 returned: " + result);

            // Log inputs
            if (a) {
                var hex = "";
                for (var i = 0; i < a.length; i++) hex += ("0" + (a[i] & 0xFF).toString(16)).slice(-2);
                log("INPUT", "token: " + hex);
            }
            if (b) {
                var hex = "";
                for (var i = 0; i < b.length; i++) hex += ("0" + (b[i] & 0xFF).toString(16)).slice(-2);
                log("INPUT", "time_bytes: " + hex);
            }
            if (c) {
                var hex = "";
                for (var i = 0; i < c.length; i++) hex += ("0" + (c[i] & 0xFF).toString(16)).slice(-2);
                log("INPUT", "hmac: " + hex);
            }
            return result;
        };
        log("HOOK", "_z05 hooked");
    } catch(e) { log("ERR", "_z05: " + e); }

    // Hook SharedPreferences to get stored key material
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            if (key === "vkb" || key === "vit" || key === "_p52") {
                log("SP_READ", key + " = " + (val ? val : "null"));
            }
            return val;
        };
        SP.putString.implementation = function(key, value) {
            if (key === "vkb" || key === "vit" || key === "_p52") {
                log("SP_WRITE", key + " = " + (value ? value : "null"));
            }
            return this.putString(key, value);
        };
        log("HOOK", "SP hooked");
    } catch(e) { log("ERR", "SP: " + e); }

    // Hook X5 encrypt/decrypt
    try {
        var X5 = Java.use("X5");
        X5.b.overload("[B").implementation = function(input) {
            var r = this.b(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(r.length, 32); i++) oh += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            log("X5_ENC", "input=" + ih + " output=" + oh);
            return r;
        };
        X5.a.overload("[B").implementation = function(input) {
            var r = this.a(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(r.length, 32); i++) oh += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            log("X5_DEC", "input=" + ih + " output=" + oh);
            return r;
        };
        X5.f.implementation = function() {
            var r = this.f();
            var hex = "";
            for (var i = 0; i < r.length; i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            log("KEY_BLOB", "X5.f() = " + hex + " (len=" + r.length + ")");
            return r;
        };
        log("HOOK", "X5 hooked");
    } catch(e) { log("ERR", "X5: " + e); }

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            log("SECRET_KEY", "algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            return this.$init(bytes, algo);
        };
        log("HOOK", "SecretKeySpec hooked");
    } catch(e) { log("ERR", "SKS: " + e); }

    // Hook Cipher.init
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    log("CIPHER_KEY", "mode=" + (mode==1?"ENC":"DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
        };
        log("HOOK", "Cipher.init hooked");
    } catch(e) { log("ERR", "Cipher: " + e); }

    // Bypass integrity and debug
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
        Java.use("android.os.Debug").waitForDebugger.implementation = function() {};
        log("HOOK", "Integrity+Debug bypassed");
    } catch(e) { log("ERR", "Bypass: " + e); }

    // Try to find the obfuscated HTTP client class
    try {
        // The app uses class 'v' as API client based on earlier analysis
        // Let's hook all string-returning methods of class 'v'
        var v_class = Java.use("v");
        var methods = v_class.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            if (ret === "java.lang.String") {
                log("CLASS_V", "method: " + name + " -> String");
            }
        }
    } catch(e) { log("ERR", "class v: " + e); }

    // Hook ALL methods that return String in app classes
    try {
        var classes = ["v", "F0", "G4", "X5", "N9"];
        for (var ci = 0; ci < classes.length; ci++) {
            try {
                var cls = Java.use(classes[ci]);
                var meths = cls.class.getDeclaredMethods();
                for (var mi = 0; mi < meths.length; mi++) {
                    var m = meths[mi];
                    var ret = m.getReturnType().getName();
                    var name = m.getName();
                    if (ret === "java.lang.String" && !name.startsWith("access$")) {
                        log("ENUM", classes[ci] + "." + name + " -> String");
                    }
                }
            } catch(e2) {}
        }
    } catch(e) { log("ERR", "Enum: " + e); }

    log("INIT", "All hooks installed. App will start now...");
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

# Resume the app
device.resume(pid)
print(f'[*] App resumed. Waiting 20s for auth flow...')
time.sleep(20)

# Summary
print('\n=== CAPTURED VALUES ===')
for c in captured:
    tag = c.get('tag', '')
    val = c.get('value', c.get('data', ''))
    if tag in ('AUTH_KEY', 'DIRECT_KEY', 'AUTH_HEADER', 'KEY_BLOB', 'SECRET_KEY', 'CIPHER_KEY'):
        print(f'  {tag}: {val}')

session.detach()
print('[*] Done')
