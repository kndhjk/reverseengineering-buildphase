#!/usr/bin/env python3
"""Hook OkHttp by finding obfuscated class names."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')

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
            console.log("[_z05] AUTH_VALUE: " + result);
            capturedAuth = result;
            return result;
        };
    } catch(e) {}

    // Hook class v.d() and v.e() which return strings
    try {
        var v_cls = Java.use("v");
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
        v_cls.b.overload("v", "java.lang.String", "java.lang.String", "java.lang.String", "H1").implementation = function(self, url, method, body, callback) {
            console.log("[v.b] url=" + url + " method=" + method + " body=" + (body ? body.substring(0, 200) : "null"));
            return this.b(self, url, method, body, callback);
        };
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(call, url, callback) {
            console.log("[v.c] url=" + url);
            return this.c(call, url, callback);
        };
        console.log("[HOOK] class v");
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Hook class u (extends G8, implements v3 - might be HTTP client)
    try {
        var u_cls = Java.use("u");
        var methods = u_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            var params = m.getParameterTypes();
            var paramStr = [];
            for (var j = 0; j < params.length; j++) paramStr.push(params[j].getName());
            console.log("[CLASS_U] " + name + "(" + paramStr.join(", ") + ") -> " + ret);
        }
    } catch(e) { console.log("[ERR] class u: " + e); }

    // Hook ALL string-returning methods in ALL single-letter classes
    try {
        var singleClasses = ["a", "B", "C", "e", "F", "G", "H", "I", "k", "l", "M", "N", "o", "p", "P", "Q", "S", "U", "V", "W", "X", "Y", "Z"];
        singleClasses.forEach(function(clsName) {
            try {
                var cls = Java.use(clsName);
                var methods = cls.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var ret = m.getReturnType().getName();
                    var name = m.getName();
                    var params = m.getParameterTypes();
                    if (ret === "java.lang.String" && params.length === 0) {
                        (function(cn, mn) {
                            try {
                                cls[mn].implementation = function() {
                                    var r = this[mn]();
                                    if (r && r.length > 10) {
                                        console.log("[" + cn + "." + mn + "] " + r.substring(0, 200));
                                    }
                                    return r;
                                };
                            } catch(e3) {}
                        })(clsName, name);
                    }
                }
            } catch(e2) {}
        });
    } catch(e) { console.log("[ERR] single classes: " + e); }

    // Bypass
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}

    console.log("[INIT] Ready.");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        payload = str(msg.get('payload', ''))
        print(payload)
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower() and 'already' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()
time.sleep(2)

# Tap Generate
print('[*] Tapping GENERATE...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '216', '448'], timeout=5)
print('[*] Waiting 20s...')
time.sleep(20)

session.detach()
print('[*] Done')
