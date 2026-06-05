#!/usr/bin/env python3
"""Trace _z05 memory reads to find the real key location."""
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

var coreLib = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("reverseai-core") !== -1) {
        coreLib = mods[i];
        break;
    }
}

if (coreLib) {
    console.log("[CORE] " + coreLib.name + " at " + coreLib.base + " size=" + coreLib.size);

    // Read the entire library
    var libData = coreLib.base.readByteArray(coreLib.size);
    var view = new Uint8Array(libData);

    // Find the .fake_text section
    // From our analysis: offset=0xf100 size=0x2e2f
    var fakeTextOffset = 0xf100;
    var fakeTextSize = 0x2e2f;
    var fakeTextAddr = coreLib.base.add(fakeTextOffset);

    console.log("[FAKE_TEXT] at " + fakeTextAddr + " size=" + fakeTextSize);

    // Read the fake_text section
    var fakeText = fakeTextAddr.readByteArray(fakeTextSize);
    var fakeView = new Uint8Array(fakeText);

    // Look for patterns that could be encoded keys
    // Try XOR with common keys
    console.log("[DECODE] Trying XOR decodings...");

    // Try XOR with 0xaa (common in the data)
    var xor_aa = "";
    for (var i = 0; i < Math.min(fakeTextSize, 128); i++) {
        var byte = fakeView[i] ^ 0xaa;
        xor_aa += String.fromCharCode(byte);
    }
    console.log("[XOR_0xaa] " + xor_aa.substring(0, 64));

    // Try XOR with 0xe2
    var xor_e2 = "";
    for (var i = 0; i < Math.min(fakeTextSize, 128); i++) {
        var byte = fakeView[i] ^ 0xe2;
        xor_e2 += String.fromCharCode(byte);
    }
    console.log("[XOR_0xe2] " + xor_e2.substring(0, 64));

    // Try XOR with 0x23
    var xor_23 = "";
    for (var i = 0; i < Math.min(fakeTextSize, 128); i++) {
        var byte = fakeView[i] ^ 0x23;
        xor_23 += String.fromCharCode(byte);
    }
    console.log("[XOR_0x23] " + xor_23.substring(0, 64));

    // Look for the key derivation labels in the binary
    var labels = ["d-key/v1", "verdict-wrap-aead-key/v1", "verdict-wrap-iv/v1", "verdict-wrap-xor-mask/v1"];
    for (var l = 0; l < labels.length; l++) {
        var label = labels[l];
        for (var i = 0; i < view.length - label.length; i++) {
            var found = true;
            for (var j = 0; j < label.length; j++) {
                if (view[i + j] !== label.charCodeAt(j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                console.log("[LABEL] '" + label + "' at " + hex(coreLib.base.add(i)));
                // Show data around this label
                var ctx = coreLib.base.add(i).readByteArray(64);
                var ctxView = new Uint8Array(ctx);
                var hexStr = "";
                for (var j = 0; j < 64; j++) {
                    hexStr += ("0" + ctxView[j].toString(16)).slice(-2);
                }
                console.log("[LABEL_CTX] " + hexStr);
            }
        }
    }

    // Now hook RegisterNatives to find _z05
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

                if (name === "_z05") {
                    console.log("[FOUND] _z05 at " + fnPtr);

                    // Disassemble the function to find memory reads
                    var fnCode = fnPtr.readByteArray(512);
                    var fnView = new Uint8Array(fnCode);

                    // Look for LEA instructions that reference data
                    // In x86_64, LEA with RIP-relative: 0x8d 0x05 <disp32>
                    console.log("[DISASM] Scanning _z05 for data references...");
                    for (var j = 0; j < 512 - 6; j++) {
                        if (fnView[j] === 0x8d && fnView[j+1] === 0x05) {
                            var disp = fnView[j+2] | (fnView[j+3] << 8) | (fnView[j+4] << 16) | (fnView[j+5] << 24);
                            if (disp > 0x80000000) disp = disp - 0x100000000;
                            var target = fnPtr.add(j + 6 + disp);
                            console.log("[LEA] at " + hex(fnPtr.add(j)) + " -> " + target);

                            // Read data at target
                            try {
                                var data = target.readByteArray(32);
                                var dataView = new Uint8Array(data);
                                var hexStr = "";
                                for (var k = 0; k < 32; k++) {
                                    hexStr += ("0" + dataView[k].toString(16)).slice(-2);
                                }
                                console.log("[LEA_DATA] " + hexStr);
                            } catch(e) {}
                        }
                    }

                    // Hook _z05 with detailed memory tracing
                    Interceptor.attach(fnPtr, {
                        onEnter: function(args) {
                            console.log("[_z05] ===== CALLED =====");
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
                            } catch(e) {
                                console.log("[_z05] return error: " + e);
                            }
                        }
                    });
                }
            }
        }
    });
}

function hex(n) {
    return "0x" + n.toString(16);
}

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
time.sleep(10)

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
