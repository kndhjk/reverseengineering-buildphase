#!/usr/bin/env python3
"""Hook _z05 and replace return value to test different key formats."""
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

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var newStringUTF = vtable.add(169 * Process.pointerSize).readPointer();

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
                    },
                    onLeave: function(retval) {
                        // Read the original return value
                        try {
                            var newStrFn = new NativeFunction(newStringUTF, 'pointer', ['pointer', 'pointer']);
                            // The retval is a jstring - we can't easily read it here
                            // Instead, let's replace it with a new string
                            var jniEnv = env.handle;
                            var testKey = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7";
                            var newJstring = newStrFn(jniEnv, Memory.allocUtf8String(testKey));
                            console.log("[_z05] Replaced return with shared key");
                            retval.replace(newJstring);
                        } catch(e) {
                            console.log("[_z05] replace error: " + e);
                        }
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

subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "540", "291"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "text", "cat"], timeout=5)
time.sleep(0.5)
subprocess.run([ADB, "-s", DEVICE, "shell", "input", "tap", "216", "448"], timeout=5)
print("[*] Tapped Generate. Waiting 30s...")
time.sleep(30)

session.detach()
print("[*] Done")
