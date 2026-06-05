#!/usr/bin/env python3
"""Hook crypto operations at the earliest possible point."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"
DEVICE = "emulator-5554"

device = frida.get_device(DEVICE, timeout=5)
subprocess.run([ADB, "-s", DEVICE, "shell", "am", "force-stop", PACKAGE], timeout=10)
time.sleep(1)
pid = device.spawn([PACKAGE])
session = device.attach(pid)

JS = r"""
"use strict";

console.log("[INIT] Loading early hooks...");

// Hook Cipher.init BEFORE Java.perform
// This catches crypto operations during app startup
var Cipher_init = null;
var Cipher_doFinal = null;

// Try to find Cipher class
Java.perform(function() {
    console.log("[JAVA] Java.perform OK (early)");

    // Bypass
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}

    // Hook Cipher immediately
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher_init = Cipher.init;
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER] mode=" + (mode === 1 ? "ENC" : "DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            if (params) {
                try {
                    var GCM = Java.use("javax.crypto.spec.GCMParameterSpec");
                    if (params instanceof GCM) {
                        var iv = params.getIV();
                        var ivHex = "";
                        for (var i = 0; i < iv.length; i++) ivHex += ("0" + (iv[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[CIPHER] GCM IV=" + ivHex);
                    }
                } catch(e3) {}
            }
            return this.init(mode, key, params);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 64); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[CIPHER] doFinal algo=" + this.getAlgorithm() + " in=" + ih + " out=" + oh);
            return result;
        };
        console.log("[HOOK] Cipher OK");
    } catch(e) { console.log("[ERR] Cipher: " + e); }

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            console.log("[SKS] algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            return this.$init(bytes, algo);
        };
        console.log("[HOOK] SKS OK");
    } catch(e) {}

    // Hook KeyGenerator
    try {
        var KeyGen = Java.use("javax.crypto.KeyGenerator");
        KeyGen.generateKey.implementation = function() {
            var key = this.generateKey();
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[KEYGEN] " + hex);
                }
            } catch(e2) {}
            return key;
        };
        console.log("[HOOK] KeyGen OK");
    } catch(e) {}

    // Hook X5.a (decrypt)
    try {
        var X5 = Java.use("X5");
        X5.a.overload("[B").implementation = function(input) {
            var result = this.a(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5_DEC] " + ih + " -> " + oh);
            return result;
        };
        console.log("[HOOK] X5.a OK");
    } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[Z05] " + result);
            return result;
        };
        console.log("[HOOK] _z05 OK");
    } catch(e) {}

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val : "null"));
            return val;
        };
        console.log("[HOOK] SP OK");
    } catch(e) {}

    // Now trigger the integrity check to force crypto operations
    try {
        var X5 = Java.use("X5");
        var instance = X5.$new();
        console.log("[TRIGGER] Calling X5.i()...");
        var result = instance.i();
        console.log("[TRIGGER] X5.i() = " + result);
    } catch(e) {
        console.log("[TRIGGER] X5.i() error: " + e);
    }

    console.log("[INIT] All hooks installed. Tap Generate...");
});
"""

def on_message(msg, data):
    if msg.get("type") == "send":
        print(msg.get("payload", ""))
    elif msg.get("type") == "error":
        desc = msg.get("description", "")
        if "send" not in desc.lower() and "cast" not in desc.lower() and "properties" not in desc.lower():
            print(f"[ERR] {desc[:200]}")

script = session.create_script(JS, runtime="v8")
script.on("message", on_message)
script.load()

device.resume(pid)
time.sleep(10)

subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "540", "291"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "text", "cat"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "216", "448"], timeout=5)
print("[*] Tapped Generate. Waiting 30s...")
time.sleep(30)

session.detach()
print("[*] Done")
