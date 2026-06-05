#!/usr/bin/env python3
"""Hook all crypto operations to find the real API key."""
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

console.log("[INIT] Loading...");

var allCapture = [];

Java.perform(function() {
    // Bypass
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}

    // Hook Cipher.init
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER_KEY] mode=" + (mode === 1 ? "ENC" : "DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                    allCapture.push("CIPHER_KEY: " + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[CIPHER_DATA] algo=" + this.getAlgorithm() + " in=" + ih + " out=" + oh);
            allCapture.push("CIPHER_DATA: " + oh);
            return result;
        };
    } catch(e) {}

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            console.log("[SKS] algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            allCapture.push("SKS: " + hex);
            return this.$init(bytes, algo);
        };
    } catch(e) {}

    // Hook X5 decrypt
    try {
        var X5 = Java.use("X5");
        X5.a.overload("[B").implementation = function(input) {
            var result = this.a(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5_DEC] " + ih + " -> " + oh);
            allCapture.push("X5_DEC: " + oh);
            return result;
        };
    } catch(e) {}

    // Hook Mac
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.init.overload("java.security.Key").implementation = function(key) {
            try {
                var kb = key.getEncoded();
                var hex = "";
                for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                console.log("[MAC_KEY] algo=" + this.getAlgorithm() + " key=" + hex);
            } catch(e2) {}
            return this.init(key);
        };
    } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[Z05] " + result);
            allCapture.push("Z05: " + result);
            return result;
        };
    } catch(e) {}

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val : "null"));
            return val;
        };
    } catch(e) {}

    // Hook class v.e
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
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
time.sleep(5)

subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "540", "291"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "text", "cat"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "216", "448"], timeout=5)
print("[*] Tapped Generate. Waiting 30s...")
time.sleep(30)

session.detach()
print("[*] Done")
