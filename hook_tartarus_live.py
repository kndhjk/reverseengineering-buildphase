#!/usr/bin/env python3
"""Hook tartarus APK to extract the independent API key."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.cs702.tartarus"
DEVICE = "emulator-5554"

device = frida.get_device(DEVICE, timeout=5)
print(f'[*] Device: {device.name}')

# Force stop and spawn
subprocess.run([ADB, '-s', DEVICE, 'shell', 'am', 'force-stop', PACKAGE], timeout=10)
time.sleep(1)

pid = device.spawn([PACKAGE])
print(f'[*] Spawned PID: {pid}')
session = device.attach(pid)

JS = r'''
"use strict";

var capturedKeys = [];

function hex(arr, max) {
    max = max || arr.length;
    var h = "";
    for (var i = 0; i < Math.min(arr.length, max); i++) h += ("0" + (arr[i] & 0xFF).toString(16)).slice(-2);
    return h;
}

Java.perform(function() {
    console.log("[INIT] Loading tartarus hooks...");

    // 1. Call all ImagePipeline methods to get decoded strings
    try {
        var IPC = Java.use("com.example.playground.network.ImagePipeline$Companion");
        var methods = ["a", "b", "c", "d", "i", "j"];
        methods.forEach(function(m) {
            try {
                var r = IPC[m]();
                console.log("[IPC." + m + "] " + r);
            } catch(e) {}
        });
    } catch(e) { console.log("[ERR] IPC: " + e); }

    // 2. Hook AssetProbe methods
    try {
        var AP = Java.use("com.example.playground.utils.AssetProbe");
        var probe = AP.$new();
        try {
            var ep = probe.probeEndpoint();
            console.log("[probeEndpoint] " + ep);
            capturedKeys.push({method: "probeEndpoint", value: ep});
        } catch(e) { console.log("[ERR] probeEndpoint: " + e); }
        try {
            var gate = probe.probeGate();
            console.log("[probeGate] " + gate);
            capturedKeys.push({method: "probeGate", value: gate});
        } catch(e) { console.log("[ERR] probeGate: " + e); }

        // Hook for future calls
        AP.probeEndpoint.implementation = function() {
            var r = this.probeEndpoint();
            console.log("[HOOK_probeEndpoint] " + r);
            capturedKeys.push({method: "probeEndpoint_hook", value: r});
            return r;
        };
        AP.probeGate.implementation = function() {
            var r = this.probeGate();
            console.log("[HOOK_probeGate] " + r);
            capturedKeys.push({method: "probeGate_hook", value: r});
            return r;
        };
        console.log("[HOOK] AssetProbe");
    } catch(e) { console.log("[ERR] AssetProbe: " + e); }

    // 3. Hook loadPalette - builds the HTTP request
    try {
        var AP = Java.use("com.example.playground.utils.AssetProbe");
        AP.loadPalette.implementation = function(cacheDir) {
            console.log("[loadPalette] called");
            var r = this.loadPalette(cacheDir);
            console.log("[loadPalette] result=" + (r ? r.substring(0, 200) : "null"));
            return r;
        };
        console.log("[HOOK] loadPalette");
    } catch(e) { console.log("[ERR] loadPalette: " + e); }

    // 4. Hook PaletteProbe.readPalette
    try {
        var PP = Java.use("com.example.playground.network.PaletteProbe");
        PP.readPalette.implementation = function() {
            var r = this.readPalette();
            console.log("[readPalette] " + r);
            capturedKeys.push({method: "readPalette", value: r});
            return r;
        };
        console.log("[HOOK] PaletteProbe");
    } catch(e) { console.log("[ERR] PaletteProbe: " + e); }

    // 5. Hook AssetWarmup.warmupNative
    try {
        var AW = Java.use("com.example.playground.network.AssetWarmup");
        AW.warmupNative.implementation = function() {
            var r = this.warmupNative();
            console.log("[warmupNative] " + r);
            capturedKeys.push({method: "warmupNative", value: r});
            return r;
        };
        console.log("[HOOK] AssetWarmup");
    } catch(e) { console.log("[ERR] AssetWarmup: " + e); }

    // 6. Hook RuntimeProbe
    try {
        var RP = Java.use("com.example.playground.util.RuntimeProbe");
        RP.inspectRuntime.implementation = function() {
            console.log("[inspectRuntime] -> false");
            return false;
        };
        console.log("[HOOK] RuntimeProbe");
    } catch(e) {}

    // 7. Hook OkHttp request builder (A0.p)
    try {
        var RB = Java.use("A0.p");
        RB.p.overload("java.lang.String").implementation = function(url) {
            console.log("[A0.p] url=" + url);
            return this.p(url);
        };
        RB.m.overload("java.lang.String", "java.lang.String").implementation = function(name, value) {
            console.log("[A0.p] header=" + name + " = " + value);
            if (name.toLowerCase() === "authorization") {
                capturedKeys.push({method: "auth_header", value: value});
            }
            return this.m(name, value);
        };
        console.log("[HOOK] A0.p (RequestBuilder)");
    } catch(e) { console.log("[ERR] A0.p: " + e); }

    // 8. Hook G1.j.b (token factory)
    try {
        var TF = Java.use("G1.j");
        TF.b.implementation = function() {
            var r = this.b();
            console.log("[G1.j.b] token=" + r);
            capturedKeys.push({method: "G1.j.b", value: r});
            return r;
        };
        console.log("[HOOK] G1.j.b");
    } catch(e) { console.log("[ERR] G1.j.b: " + e); }

    // 9. Hook FrameAssembler
    try {
        var FA = Java.use("com.example.playground.network.FrameAssembler");
        FA.composeFrame.overload("java.lang.String").implementation = function(prompt) {
            var r = this.composeFrame(prompt);
            console.log("[composeFrame] prompt=" + prompt + " result=" + r);
            return r;
        };
        console.log("[HOOK] FrameAssembler");
    } catch(e) { console.log("[ERR] FrameAssembler: " + e); }

    // 10. Hook ImagePipeline.routeBase
    try {
        var IPC = Java.use("com.example.playground.network.ImagePipeline$Companion");
        IPC.e.overload("java.lang.String").implementation = function(url) {
            var r = this.e(url);
            console.log("[routeBase] in=" + url + " out=" + r);
            return r;
        };
        console.log("[HOOK] routeBase");
    } catch(e) { console.log("[ERR] routeBase: " + e); }

    // 11. Bypass root/debug detection
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        Debug.waitForDebugger.implementation = function() {};
        console.log("[HOOK] Debug bypassed");
    } catch(e) {}

    // 12. Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            if (val && val.length > 5) {
                console.log("[SP] getString(" + key + ") = " + val.substring(0, 200));
            }
            return val;
        };
        console.log("[HOOK] SP");
    } catch(e) { console.log("[ERR] SP: " + e); }

    // 13. Hook JSONObject.getString for 'signature'
    try {
        var JO = Java.use("org.json.JSONObject");
        JO.getString.overload("java.lang.String").implementation = function(name) {
            var r = this.getString(name);
            if (name === "signature" || name === "token") {
                console.log("[JSON] getString(" + name + ") = " + r);
            }
            return r;
        };
        console.log("[HOOK] JSONObject");
    } catch(e) {}

    console.log("[INIT] All hooks installed. App starting...");
});
'''

captured = []
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

device.resume(pid)
print(f'[*] App resumed. Waiting 30s...')
print('[*] TAP THE GENERATE BUTTON IN THE APP!')
time.sleep(30)

# Print summary
print('\n=== SUMMARY ===')
session.detach()
print('[*] Done')
