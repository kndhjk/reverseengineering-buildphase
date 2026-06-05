#!/usr/bin/env python3
"""Complete hook: capture _z05, class v, AND the actual HTTP Authorization header."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')

JS = r'''
"use strict";

var authValues = [];

Java.perform(function() {
    console.log("[INIT] Loading...");

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            authValues.push({_z05: result});
            return result;
        };
    } catch(e) {}

    // Hook class v.b which takes (v, String, String, String, H1) - the API call
    try {
        var v_cls = Java.use("v");
        v_cls.b.overload("v", "java.lang.String", "java.lang.String", "java.lang.String", "H1").implementation = function(self, url, method, body, callback) {
            console.log("[v.b] === API CALL ===");
            console.log("[v.b] url=" + url);
            console.log("[v.b] method=" + method);
            console.log("[v.b] body=" + (body ? body.substring(0, 500) : "null"));
            var r = this.b(self, url, method, body, callback);
            console.log("[v.b] returned");
            return r;
        };
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(call, url, callback) {
            console.log("[v.c] url=" + (url ? url.substring(0, 200) : "null"));
            return this.c(call, url, callback);
        };
        v_cls.d.overload("r5", "java.util.Set", "boolean").implementation = function(a, b, c) {
            var r = this.d(a, b, c);
            console.log("[v.d] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        console.log("[HOOK] class v");
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Hook ALL methods in ALL classes that take String and return something
    // Focus on finding where Authorization header is set
    try {
        // Hook classes that might be request builders
        var reqClasses = ["A7", "B7", "N6", "p7"];
        reqClasses.forEach(function(cn) {
            try {
                var cls = Java.use(cn);
                var methods = cls.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var name = m.getName();
                    var ret = m.getReturnType().getName();
                    var params = m.getParameterTypes();
                    var paramStr = [];
                    for (var j = 0; j < params.length; j++) paramStr.push(params[j].getName());
                    console.log("[" + cn + "] " + name + "(" + paramStr.join(", ") + ") -> " + ret);
                }
            } catch(e2) {}
        });
    } catch(e) {}

    // Hook OkHttp3 addHeader by finding the class dynamically
    try {
        // Search for classes that have addHeader method
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.startsWith("nz.ac.auckland") || className.length > 5) return;
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    for (var i = 0; i < methods.length; i++) {
                        var m = methods[i];
                        var name = m.getName();
                        if (name === "addHeader" || name === "header" || name === "setRequestProperty") {
                            var ret = m.getReturnType().getName();
                            var params = m.getParameterTypes();
                            if (params.length === 2 && params[0].getName() === "java.lang.String" && params[1].getName() === "java.lang.String") {
                                console.log("[FOUND] " + className + "." + name + "(String, String) -> " + ret);
                                // Hook it
                                (function(cn, mn) {
                                    try {
                                        cls[mn].overload("java.lang.String", "java.lang.String").implementation = function(k, v) {
                                            console.log("[" + cn + "." + mn + "] " + k + " = " + v);
                                            if (k.toLowerCase() === "authorization") {
                                                authValues.push({header: v});
                                            }
                                            return this[k === "authorization" ? mn : mn](k, v);
                                        };
                                    } catch(e3) {}
                                })(className, name);
                            }
                        }
                    }
                } catch(e2) {}
            },
            onComplete: function() {
                console.log("[INIT] Class enumeration complete.");
            }
        });
    } catch(e) { console.log("[ERR] enum: " + e); }

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

    console.log("[INIT] All hooks installed.");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        print(msg.get('payload', ''))
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower() and 'already' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()
time.sleep(8)  # Wait for class enumeration

# Tap Generate
print('[*] Tapping GENERATE...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '216', '448'], timeout=5)
print('[*] Waiting 20s...')
time.sleep(20)

session.detach()
print('[*] Done')
