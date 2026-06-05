#!/usr/bin/env python3
"""Deep hook vitality - capture ALL network and crypto activity."""
import frida
import time
import sys
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.se702.reverseai"

device = frida.get_device('emulator-5554', timeout=5)
subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'am', 'force-stop', PACKAGE], timeout=10)
time.sleep(1)
pid = device.spawn([PACKAGE])
print(f'[*] Spawned PID: {pid}')
session = device.attach(pid)

JS = r'''
"use strict";

function hex(arr, max) {
    max = max || arr.length;
    var h = "";
    for (var i = 0; i < Math.min(arr.length, max); i++) h += ("0" + (arr[i] & 0xFF).toString(16)).slice(-2);
    return h;
}

Java.perform(function() {
    console.log("[INIT] Deep hooks loading...");

    // Hook _z05 with full input/output logging
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            console.log("[_z05] Called with:");
            if (a) console.log("[_z05] arg0 (token): len=" + a.length + " hex=" + hex(a, 64));
            if (b) console.log("[_z05] arg1 (time): len=" + b.length + " hex=" + hex(b, 16));
            if (c) console.log("[_z05] arg2 (hmac): len=" + c.length + " hex=" + hex(c, 16));
            var result = this._z05(a, b, c);
            console.log("[_z05] RETURNED: " + result);
            return result;
        };
        console.log("[HOOK] _z05");
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook _z06 (processes auth response)
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z06.implementation = function(a) {
            console.log("[_z06] Called with: " + hex(a, 128) + " len=" + (a ? a.length : 0));
            this._z06(a);
            console.log("[_z06] Done");
        };
        console.log("[HOOK] _z06");
    } catch(e) { console.log("[ERR] _z06: " + e); }

    // Hook ALL String-returning methods in app classes
    try {
        var classes = ["v", "F0", "G4", "X5"];
        classes.forEach(function(clsName) {
            try {
                var cls = Java.use(clsName);
                var methods = cls.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var ret = m.getReturnType().getName();
                    var name = m.getName();
                    var params = m.getParameterTypes();
                    if (ret === "java.lang.String" && params.length === 0) {
                        (function(n) {
                            cls[n].implementation = function() {
                                var r = this[n]();
                                console.log("[" + clsName + "." + n + "] = " + (r ? r.substring(0, 200) : "null"));
                                return r;
                            };
                        })(name);
                        console.log("[HOOK] " + clsName + "." + name + " -> String");
                    }
                }
            } catch(e) {}
        });
    } catch(e) { console.log("[ERR] class hooks: " + e); }

    // Hook SharedPreferences for ALL keys
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] getString(" + key + ") = " + (val ? val.substring(0, 200) : "null"));
            return val;
        };
        SP.putString.implementation = function(key, value) {
            console.log("[SP] putString(" + key + ") = " + (value ? value.substring(0, 200) : "null"));
            return this.putString(key, value);
        };
        console.log("[HOOK] SP");
    } catch(e) { console.log("[ERR] SP: " + e); }

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            console.log("[SKS] algo=" + algo + " len=" + bytes.length + " hex=" + hex(bytes, 64));
            return this.$init(bytes, algo);
        };
        console.log("[HOOK] SKS");
    } catch(e) {}

    // Hook Cipher
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) console.log("[CIPHER] mode=" + (mode==1?"ENC":"DEC") + " algo=" + this.getAlgorithm() + " key=" + hex(kb, 64));
            } catch(e2) {}
            return this.init(mode, key, params);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[CIPHER] doFinal input_len=" + input.length);
            var r = this.doFinal(input);
            console.log("[CIPHER] doFinal output_len=" + r.length + " hex=" + hex(r, 32));
            return r;
        };
        console.log("[HOOK] Cipher");
    } catch(e) {}

    // Hook Mac (HMAC)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function(input) {
            var r = this.doFinal(input);
            console.log("[MAC] doFinal algo=" + this.getAlgorithm() + " result=" + hex(r, 32));
            return r;
        };
        Mac.init.overload("java.security.Key").implementation = function(key) {
            try {
                var kb = key.getEncoded();
                console.log("[MAC] init algo=" + this.getAlgorithm() + " key=" + hex(kb, 64));
            } catch(e2) {}
            return this.init(key);
        };
        console.log("[HOOK] Mac");
    } catch(e) {}

    // Hook MessageDigest
    try {
        var MD = Java.use("java.security.MessageDigest");
        MD.digest.overload("[B").implementation = function(input) {
            var r = this.digest(input);
            console.log("[MD] digest algo=" + this.getAlgorithm() + " input_len=" + input.length + " result=" + hex(r, 32));
            return r;
        };
        console.log("[HOOK] MD");
    } catch(e) {}

    // Hook Base64
    try {
        var B64 = Java.use("android.util.Base64");
        B64.encodeToString.overload("[B", "int").implementation = function(input, flags) {
            var r = this.encodeToString(input, flags);
            if (input.length >= 16) console.log("[B64] encode len=" + input.length + " hex=" + hex(input, 32) + " -> " + r.substring(0, 60));
            return r;
        };
        B64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            var r = this.decode(str, flags);
            if (r.length >= 16) console.log("[B64] decode " + str.substring(0, 40) + " -> len=" + r.length + " hex=" + hex(r, 32));
            return r;
        };
        console.log("[HOOK] B64");
    } catch(e) {}

    // Bypass integrity
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
        console.log("[HOOK] Bypass OK");
    } catch(e) {}

    console.log("[INIT] All hooks installed. Waiting for app activity...");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        print(f'[MSG] {msg.get("payload", "")}')
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()

device.resume(pid)
print('[*] App resumed. Waiting 30s for user interaction...')
print('[*] TAP THE "GENERATE" BUTTON IN THE APP NOW!')
time.sleep(30)

session.detach()
print('[*] Done')
