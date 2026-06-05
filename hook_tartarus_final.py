#!/usr/bin/env python3
"""Hook tartarus with comprehensive anti-detection bypass."""
import frida
import time
import subprocess
import sys

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
PACKAGE = "nz.ac.auckland.cs702.tartarus"
DEVICE = "emulator-5554"

device = frida.get_device(DEVICE, timeout=5)
subprocess.run([ADB, "-s", DEVICE, "shell", "am", "force-stop", PACKAGE], timeout=10)
time.sleep(1)
pid = device.spawn([PACKAGE])
print(f"[*] Spawned PID: {pid}")
session = device.attach(pid)

JS_BYPASS = r'''
console.log("[INIT] Loading bypass...");

// Replace exit/abort to prevent self-kill
var exit_ptr = Module.findExportByName("libc.so", "exit");
if (exit_ptr) {
    Interceptor.replace(exit_ptr, new NativeCallback(function(code) {
        console.log("[BLOCKED] exit(" + code + ")");
    }, "void", ["int"]));
}

var abort_ptr = Module.findExportByName("libc.so", "abort");
if (abort_ptr) {
    Interceptor.replace(abort_ptr, new NativeCallback(function() {
        console.log("[BLOCKED] abort()");
    }, "void", []));
}

// Block /proc reads
var open_ptr = Module.findExportByName("libc.so", "open");
if (open_ptr) {
    Interceptor.attach(open_ptr, {
        onEnter: function(args) {
            try {
                var path = args[0].readUtf8String();
                if (path && path.indexOf("/proc/") !== -1) {
                    this.block = true;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
        }
    });
}

// Hide frida from strstr
var strstr_ptr = Module.findExportByName("libc.so", "strstr");
if (strstr_ptr) {
    Interceptor.attach(strstr_ptr, {
        onEnter: function(args) {
            try {
                var needle = args[1].readUtf8String();
                if (needle && needle.indexOf("frida") !== -1) this.hide = true;
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.hide) retval.replace(ptr(0));
        }
    });
}

console.log("[INIT] Bypass loaded");
'''

def on_message(msg, data):
    t = msg.get("type", "")
    p = msg.get("payload", msg.get("description", ""))
    if p:
        print(f"[{t}] {p}")

script1 = session.create_script(JS_BYPASS, runtime="v8")
script1.on("message", on_message)
script1.load()

device.resume(pid)
print("[*] Resumed with bypass")
time.sleep(8)

# Now inject Java hooks
JS_HOOKS = r'''
console.log("[JAVA] Loading Java hooks...");

Java.perform(function() {
    console.log("[JAVA] Java.perform OK");

    // Bypass RuntimeProbe
    try {
        var RP = Java.use("com.example.playground.util.RuntimeProbe");
        RP.inspectRuntime.implementation = function() {
            console.log("[BYPASS] inspectRuntime -> false");
            return false;
        };
    } catch(e) { console.log("[ERR] RP: " + e); }

    // Bypass Debug
    try {
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}

    // Call probeGate and probeEndpoint
    try {
        var AP = Java.use("com.example.playground.utils.AssetProbe");
        var probe = AP.$new();
        console.log("[KEY] probeEndpoint = " + probe.probeEndpoint());
        console.log("[KEY] probeGate = " + probe.probeGate());
    } catch(e) { console.log("[ERR] probe: " + e); }

    // Call IPC methods
    try {
        var IPC = Java.use("com.example.playground.network.ImagePipeline$Companion");
        ["a","b","c","d","i","j"].forEach(function(m) {
            try { console.log("[IPC] " + m + " = " + IPC[m]()); } catch(e) {}
        });
    } catch(e) {}

    // G1.j.b
    try { console.log("[KEY] G1.j.b = " + Java.use("G1.j").b()); } catch(e) {}

    // readPalette
    try { console.log("[KEY] readPalette = " + Java.use("com.example.playground.network.PaletteProbe").$new().readPalette()); } catch(e) {}

    // warmupNative
    try {
        var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        console.log("[KEY] warmupNative = " + Java.use("com.example.playground.network.AssetWarmup").$new(ctx).warmupNative());
    } catch(e) {}

    console.log("[DONE]");
});
'''

try:
    script2 = session.create_script(JS_HOOKS, runtime="v8")
    script2.on("message", on_message)
    script2.load()
    time.sleep(10)
except Exception as e:
    print(f"[-] Java hooks error: {e}")

session.detach()
print("[*] Done")
