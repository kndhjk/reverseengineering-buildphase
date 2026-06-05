#!/usr/bin/env python3
"""Hook _z05 native function to capture all inputs and the RETURNED key."""
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

JS = r'''
"use strict";

var z05Found = false;

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
            var sigPtr = entry.add(Process.pointerSize).readPointer();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();

            var name = namePtr.readUtf8String();
            var sig = sigPtr.readUtf8String();

            console.log("[METHOD] " + name + " " + sig + " -> " + fnPtr);

            if (name === "_z05" && !z05Found) {
                z05Found = true;
                console.log("[FOUND] _z05 at " + fnPtr);

                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z05] ===== CALLED =====");
                        try {
                            var jniEnv = Java.vm.getEnv();

                            for (var a = 2; a < 5; a++) {
                                try {
                                    var arr = jniEnv.getByteArrayElements(args[a], null);
                                    var len = jniEnv.getArrayLength(args[a]);
                                    console.log("[_z05] arg" + (a-2) + " len=" + len);
                                    if (arr && len > 0) {
                                        var hex = "";
                                        for (var b = 0; b < Math.min(len, 128); b++) {
                                            var byte = Memory.readU8(arr.add(b));
                                            hex += ("0" + byte.toString(16)).slice(-2);
                                        }
                                        console.log("[_z05] arg" + (a-2) + " hex=" + hex);
                                    }
                                } catch(e) {
                                    console.log("[_z05] arg" + (a-2) + " err=" + e);
                                }
                            }
                        } catch(e) {
                            console.log("[_z05] err=" + e);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            var jniEnv = Java.vm.getEnv();
                            var str = jniEnv.getStringUtfChars(retval, null);
                            console.log("[_z05] RETURNED: " + str);
                        } catch(e) {
                            console.log("[_z05] ret err=" + e);
                        }
                    }
                });
            }

            if (name === "_z06") {
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        try {
                            var jniEnv = Java.vm.getEnv();
                            var arr = jniEnv.getByteArrayElements(args[2], null);
                            var len = jniEnv.getArrayLength(args[2]);
                            if (arr && len > 0) {
                                var hex = "";
                                for (var b = 0; b < Math.min(len, 64); b++) {
                                    hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                }
                                console.log("[_z06] len=" + len + " hex=" + hex);
                            }
                        } catch(e) {}
                    }
                });
            }
        }
    }
});

// Bypass
try {
    Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    Java.use("X5").i.implementation = function() { return true; };
    Java.use("G4").e.implementation = function() { return true; };
    Java.use("F0").f.implementation = function() { return true; };
} catch(e) {}

console.log("[INIT] Done");
'''

captured = []
def on_message(msg, data):
    if msg.get("type") == "send":
        payload = str(msg.get("payload", ""))
        print(payload)
        if "_z05" in payload and "RETURNED" in payload:
            captured.append(payload)
    elif msg.get("type") == "error":
        desc = msg.get("description", "")
        if "send" not in desc.lower() and "cast" not in desc.lower() and "properties" not in desc.lower():
            print(f"[ERR] {desc[:200]}")

script = session.create_script(JS, runtime="v8")
script.on("message", on_message)
script.load()

device.resume(pid)
time.sleep(5)

# Type prompt and tap Generate
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "540", "291"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "text", "cat"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "216", "448"], timeout=5)
print("[*] Tapped Generate. Waiting 25s...")
time.sleep(25)

print("\n=== CAPTURED RETURN VALUES ===")
for c in captured:
    print(f"  {c}")

session.detach()
print("[*] Done")
