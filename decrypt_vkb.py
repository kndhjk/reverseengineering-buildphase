#!/usr/bin/env python3
"""Decrypt the vkb key blob by capturing the AES key from Android KeyStore."""
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

var aesKey = null;

Java.perform(function() {
    // Bypass
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}

    // Hook KeyGenerator.generateKey to capture the AES key
    try {
        var KeyGen = Java.use("javax.crypto.KeyGenerator");
        KeyGen.generateKey.implementation = function() {
            var key = this.generateKey();
            var kb = key.getEncoded();
            if (kb) {
                var hex = "";
                for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                console.log("[KEYGEN] Generated key: " + hex);
                aesKey = hex;
            }
            return key;
        };
    } catch(e) {}

    // Hook KeyStore.getKey to capture the stored key
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.implementation = function(alias, password) {
            var key = this.getKey(alias, password);
            if (key) {
                try {
                    var kb = key.getEncoded();
                    if (kb) {
                        var hex = "";
                        for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[KEYSTORE] Key for '" + alias + "': " + hex);
                        aesKey = hex;
                    }
                } catch(e2) {
                    console.log("[KEYSTORE] Key for '" + alias + "': (no encoded form)");
                }
            }
            return key;
        };
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
    } catch(e) {}

    // Hook Cipher.init to capture the AES key used for vkb decryption
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < kb.length; i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER] mode=" + (mode === 1 ? "ENC" : "DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                    aesKey = hex;
                }
            } catch(e2) {}
            if (params) {
                try {
                    var GCM = Java.use("javax.crypto.spec.GCMParameterSpec");
                    if (params instanceof GCM) {
                        var iv = params.getIV();
                        var ivHex = "";
                        for (var i = 0; i < iv.length; i++) ivHex += ("0" + (iv[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[CIPHER] GCM IV=" + ivHex + " tagLen=" + params.getTLen());
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
    } catch(e) {}

    // Hook X5.f to capture the key blob
    try {
        var X5 = Java.use("X5");
        X5.f.implementation = function() {
            var r = this.f();
            var hex = "";
            for (var i = 0; i < Math.min(r.length, 64); i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5.f] key_blob=" + hex + " len=" + r.length);
            return r;
        };
    } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[Z05] " + result);
            return result;
        };
    } catch(e) {}

    // Trigger X5.i (integrity check) manually to force crypto operations
    try {
        var X5 = Java.use("X5");
        console.log("[TRIGGER] Calling X5.i()...");
        var result = X5.i();
        console.log("[TRIGGER] X5.i() returned: " + result);
    } catch(e) {
        console.log("[TRIGGER] X5.i() error: " + e);
    }

    // Also try X5.f() to get the key blob
    try {
        var X5 = Java.use("X5");
        console.log("[TRIGGER] Calling X5.f()...");
        var blob = X5.f();
        var hex = "";
        for (var i = 0; i < Math.min(blob.length, 64); i++) hex += ("0" + (blob[i] & 0xFF).toString(16)).slice(-2);
        console.log("[TRIGGER] X5.f() = " + hex);
    } catch(e) {
        console.log("[TRIGGER] X5.f() error: " + e);
    }

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
