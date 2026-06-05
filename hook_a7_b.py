#!/usr/bin/env python3
"""Hook A7.b to capture exact headers being sent."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')

JS = r'''
"use strict";

Java.perform(function() {
    console.log("[INIT] Loading...");

    // Hook A7.b(String, String) - likely addHeader
    try {
        var A7 = Java.use("A7");
        A7.b.overload("java.lang.String", "java.lang.String").implementation = function(a, b) {
            console.log("[A7.b] " + a + " = " + b);
            return this.b(a, b);
        };
        A7.d.overload("java.lang.String").implementation = function(a) {
            console.log("[A7.d] url=" + a);
            return this.d(a);
        };
        A7.c.overload("java.lang.String", "C7").implementation = function(method, body) {
            console.log("[A7.c] method=" + method);
            return this.c(method, body);
        };
        console.log("[HOOK] A7");
    } catch(e) { console.log("[ERR] A7: " + e); }

    // Hook B7.toString to see the full request
    try {
        var B7 = Java.use("B7");
        B7.toString.implementation = function() {
            var r = this.toString();
            console.log("[B7.toString] " + r.substring(0, 500));
            return r;
        };
        console.log("[HOOK] B7");
    } catch(e) { console.log("[ERR] B7: " + e); }

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

    // Hook class v methods
    try {
        var v_cls = Java.use("v");
        v_cls.b.overload("v", "java.lang.String", "java.lang.String", "java.lang.String", "H1").implementation = function(self, url, method, body, callback) {
            console.log("[v.b] url=" + url + " method=" + method);
            console.log("[v.b] body=" + (body ? body.substring(0, 300) : "null"));
            return this.b(self, url, method, body, callback);
        };
    } catch(e) {}

    // Hook p7 (call) methods
    try {
        var p7 = Java.use("p7");
        p7.a.overload("p7").implementation = function(a) {
            var r = this.a(a);
            console.log("[p7.a] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] getString(" + key + ") = " + (val ? val.substring(0, 200) : "null"));
            return val;
        };
    } catch(e) { console.log("[ERR] SP: " + e); }

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
        print(msg.get('payload', ''))
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower() and 'already' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()
time.sleep(2)

print('[*] Tapping GENERATE...')
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap', '216', '448'], timeout=5)
print('[*] Waiting 20s...')
time.sleep(20)

session.detach()
print('[*] Done')
