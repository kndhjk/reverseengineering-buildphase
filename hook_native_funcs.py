#!/usr/bin/env python3
"""Hook obfuscated native functions to find the real key."""
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

var cryptoLib = null;
var coreLib = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("reverseai-crypto") !== -1) cryptoLib = mods[i];
    if (mods[i].name.indexOf("reverseai-core") !== -1) coreLib = mods[i];
}

if (cryptoLib) {
    console.log("[CRYPTO] " + cryptoLib.name + " at " + cryptoLib.base);

    // Hook ALL exported functions from libreverseai-crypto.so
    var exports = cryptoLib.enumerateExports();
    for (var i = 0; i < exports.length; i++) {
        var exp = exports[i];
        if (exp.type === "function") {
            (function(name, addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        console.log("[NATIVE_CALL] " + name + " called");
                        // Try to read arguments
                        for (var a = 0; a < 4; a++) {
                            try {
                                var ptr = args[a];
                                if (!ptr.isNull() && ptr.toInt32() > 0x1000) {
                                    try {
                                        var bytes = ptr.readByteArray(32);
                                        var view = new Uint8Array(bytes);
                                        var hex = "";
                                        for (var b = 0; b < 32; b++) {
                                            hex += ("0" + view[b].toString(16)).slice(-2);
                                        }
                                        console.log("[NATIVE_ARG] " + name + " arg" + a + " = " + hex);
                                    } catch(e) {}
                                }
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            try {
                                var bytes = retval.readByteArray(64);
                                var view = new Uint8Array(bytes);
                                var hex = "";
                                for (var b = 0; b < 64; b++) {
                                    hex += ("0" + view[b].toString(16)).slice(-2);
                                }
                                console.log("[NATIVE_RET] " + name + " returned: " + hex);
                            } catch(e) {}
                        }
                    }
                });
            })(exp.name, exp.address);
        }
    }
}

// Hook _z05 via RegisterNatives
var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();

Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
        var methods = args[2];
        var numMethods = args[3].toInt32();

        for (var i = 0; i < numMethods; i++) {
            var entry = methods.add(i * Process.pointerSize * 3);
            var namePtr = entry.readPointer();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
            var name = namePtr.readUtf8String();

            if (name === "_z05") {
                console.log("[FOUND] _z05 at " + fnPtr);
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z05] CALLED");
                        try {
                            var jniEnv = Java.vm.getEnv();
                            for (var a = 2; a < 5; a++) {
                                try {
                                    var len = jniEnv.getArrayLength(args[a]);
                                    var arr = jniEnv.getByteArrayElements(args[a], null);
                                    if (arr && len > 0) {
                                        var hex = "";
                                        for (var b = 0; b < Math.min(len, 128); b++) {
                                            hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                        }
                                        console.log("[_z05] arg" + (a-2) + " len=" + len + ": " + hex);
                                    }
                                } catch(e) {}
                            }
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
                        try {
                            var jniEnv = Java.vm.getEnv();
                            var str = jniEnv.getStringUtfChars(retval, null);
                            console.log("[_z05] RETURNED: " + str);
                        } catch(e) {}
                    }
                });
            }

            if (name === "_z06") {
                console.log("[FOUND] _z06 at " + fnPtr);
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z06] CALLED");
                        try {
                            var jniEnv = Java.vm.getEnv();
                            var len = jniEnv.getArrayLength(args[2]);
                            var arr = jniEnv.getByteArrayElements(args[2], null);
                            if (arr && len > 0) {
                                var hex = "";
                                for (var b = 0; b < Math.min(len, 128); b++) {
                                    hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                }
                                console.log("[_z06] input len=" + len + ": " + hex);
                            }
                        } catch(e) {}
                    }
                });
            }
        }
    }
});

// Bypass
Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}
});

console.log("[INIT] Done");
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
time.sleep(8)

# Tap Generate
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "540", "291"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "text", "cat"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "216", "448"], timeout=5)
print("[*] Tapped Generate. Waiting 30s...")
time.sleep(30)

session.detach()
print("[*] Done")
