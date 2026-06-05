#!/usr/bin/env python3
"""Find the real API key by hooking crypto operations."""
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

// Read SharedPreferences
try {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var app = ActivityThread.currentApplication();
    var ctx = app.getApplicationContext();
    var sp = ctx.getSharedPreferences("v_p1", 0);
    var all = sp.getAll();
    var keys = all.keySet().iterator();
    console.log("[SP] === SharedPreferences v_p1 ===");
    while (keys.hasNext()) {
        var key = keys.next();
        var val = all.get(key);
        console.log("[SP] " + key + " = " + val.toString());
    }
} catch(e) {
    console.log("[ERR] SP read: " + e);
}

Java.perform(function() {
    console.log("[JAVA] Performing...");

    // Bypass integrity
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}

    // Hook Cipher.init to capture AES key
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER] mode=" + (mode === 1 ? "ENC" : "DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[CIPHER] doFinal in=" + ih + " out=" + oh);
            return result;
        };
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
    } catch(e) {}

    // Hook X5 methods
    try {
        var X5 = Java.use("X5");
        X5.a.overload("[B").implementation = function(input) {
            var result = this.a(input);
            var ih = "", oh = "";
            for (var i = 0; i < Math.min(input.length, 32); i++) ih += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
            for (var i = 0; i < Math.min(result.length, 64); i++) oh += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5.a] decrypt: " + ih + " -> " + oh);
            return result;
        };
        X5.f.implementation = function() {
            var r = this.f();
            var hex = "";
            for (var i = 0; i < Math.min(r.length, 64); i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5.f] key_blob=" + hex + " len=" + r.length);
            return r;
        };
    } catch(e) {}

    // Hook _z05 via Java
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[JAVA_z05] RETURNED: " + result);
            return result;
        };
    } catch(e) {}

    // Hook class v methods
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    // Hook Base64
    try {
        var B64 = Java.use("android.util.Base64");
        B64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            var r = this.decode(str, flags);
            if (r.length >= 16) {
                var hex = "";
                for (var i = 0; i < Math.min(r.length, 64); i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
                console.log("[B64] decode len=" + r.length + " hex=" + hex);
            }
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
