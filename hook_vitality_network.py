#!/usr/bin/env python3
"""Hook vitality network layer to capture exact HTTP request."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')
print(f'[*] Attached')

JS = r'''
"use strict";

Java.perform(function() {
    console.log("[INIT] Network hooks...");

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

    // Hook ALL OkHttp3 classes
    try {
        // Hook RealCall
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.getResponseWithInterceptorChain.implementation = function() {
            var req = this.request();
            if (req) {
                console.log("[HTTP] === NEW REQUEST ===");
                console.log("[HTTP] Method: " + req.method());
                console.log("[HTTP] URL: " + req.url().toString());
                var headers = req.headers();
                for (var i = 0; i < headers.size(); i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    console.log("[HTTP] Header: " + name + " = " + value);
                }
                var body = req.body();
                if (body) {
                    try {
                        var Buffer = Java.use("okio.Buffer");
                        var buf = Buffer.$new();
                        body.writeTo(buf);
                        var bodyStr = buf.readUtf8();
                        console.log("[HTTP] Body: " + bodyStr.substring(0, 500));
                    } catch(e2) {
                        console.log("[HTTP] Body: (could not read)");
                    }
                }
            }
            return this.getResponseWithInterceptorChain();
        };
        console.log("[HOOK] RealCall");
    } catch(e) { console.log("[ERR] RealCall: " + e); }

    // Hook class v methods
    try {
        var v_cls = Java.use("v");
        v_cls.d.implementation = function() {
            var r = this.d();
            console.log("[v.d] " + (r ? r : "null"));
            return r;
        };
        v_cls.e.implementation = function() {
            var r = this.e();
            console.log("[v.e] " + (r ? r : "null"));
            return r;
        };
        console.log("[HOOK] class v");
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Bypass
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}

    console.log("[INIT] Network hooks ready.");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        print(msg.get('payload', ''))
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
print('[*] Waiting 20s...')
time.sleep(20)

session.detach()
print('[*] Done')
