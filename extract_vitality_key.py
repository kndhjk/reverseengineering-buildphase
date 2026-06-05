#!/usr/bin/env python3
"""
Extract vitality key by capturing the exact Authorization header
from the HTTP request at the moment it's sent.
"""
import frida
import time
import subprocess
import json

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')
print(f'[*] Attached')

JS = r'''
"use strict";

var capturedAuth = null;

Java.perform(function() {
    console.log("[INIT] Loading...");

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            capturedAuth = result;
            return result;
        };
    } catch(e) {}

    // Hook ALL classes that might handle HTTP
    // Enumerate all loaded classes and find ones with 'header' or 'auth' methods
    try {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.startsWith("nz.ac.auckland") || className === "v" ||
                    className.startsWith("okhttp") || className.startsWith("retrofit")) {
                    // Skip
                }
            },
            onComplete: function() {}
        });
    } catch(e) {}

    // Try to find the obfuscated OkHttp classes
    // The error said okhttp3.Request$Builder is not found
    // This means OkHttp is bundled with different package name (R8 renaming)
    // Let's try to find classes that extend or implement HTTP-related interfaces

    // Hook URL.openConnection
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            if (url.indexOf("ai.elliottwen") !== -1) {
                console.log("[URL] " + url);
            }
            return this.openConnection();
        };
        console.log("[HOOK] URL");
    } catch(e) {}

    // Hook HttpsURLConnection
    try {
        var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsConn.setRequestProperty.implementation = function(key, value) {
            if (key.toLowerCase() === "authorization") {
                console.log("[HTTPS] Authorization: " + value);
                capturedAuth = value;
            }
            return this.setRequestProperty(key, value);
        };
        console.log("[HOOK] HttpsURLConnection");
    } catch(e) { console.log("[ERR] HttpsConn: " + e); }

    // Hook setRequestProperty on URLConnection
    try {
        var URLConn = Java.use("java.net.URLConnection");
        URLConn.setRequestProperty.implementation = function(key, value) {
            if (key.toLowerCase() === "authorization" || key.toLowerCase() === "content-type") {
                console.log("[CONN] " + key + ": " + value);
            }
            return this.setRequestProperty(key, value);
        };
        console.log("[HOOK] URLConnection");
    } catch(e) {}

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

    // Hook Cipher.init
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER] mode=" + (mode==1?"ENC":"DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
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
                console.log("[MAC] init algo=" + this.getAlgorithm() + " key=" + hex);
            } catch(e2) {}
            return this.init(key);
        };
        Mac.doFinal.overload("[B").implementation = function(input) {
            var r = this.doFinal(input);
            var hex = "";
            for (var i = 0; i < Math.min(r.length, 32); i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            console.log("[MAC] doFinal algo=" + this.getAlgorithm() + " result=" + hex);
            return r;
        };
    } catch(e) {}

    console.log("[INIT] All hooks ready.");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = str(msg.get('payload', ''))
        print(payload)
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()
time.sleep(2)

# Tap Generate
print('[*] Tapping GENERATE...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '216', '448'], timeout=5)
print('[*] Waiting 25s...')
time.sleep(25)

session.detach()
print('[*] Done')
