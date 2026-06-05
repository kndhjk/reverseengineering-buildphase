#!/usr/bin/env python3
"""Trace _z05 native function execution to find the real key."""
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

console.log("[INIT] Tracing _z05...");

var z05Addr = null;
var coreLib = null;

// Find libreverseai-core.so
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("reverseai-core") !== -1) {
        coreLib = mods[i];
        break;
    }
}

if (coreLib) {
    console.log("[CORE] base=" + coreLib.base + " size=" + coreLib.size);

    // Read the entire library
    var libData = coreLib.base.readByteArray(coreLib.size);
    var view = new Uint8Array(libData);

    // Search for the string "d-key/v1" which is a key derivation label
    var dkeyStr = "d-key/v1";
    var dkeyOffset = -1;
    for (var i = 0; i < view.length - dkeyStr.length; i++) {
        var found = true;
        for (var j = 0; j < dkeyStr.length; j++) {
            if (view[i + j] !== dkeyStr.charCodeAt(j)) {
                found = false;
                break;
            }
        }
        if (found) {
            dkeyOffset = i;
            console.log("[FOUND] 'd-key/v1' at offset " + hex(i) + " (addr " + hex(coreLib.base.add(i)) + ")");
            break;
        }
    }

    // Search for "verdict-wrap-aead-key/v1"
    var verdictStr = "verdict-wrap-aead-key/v1";
    for (var i = 0; i < view.length - verdictStr.length; i++) {
        var found = true;
        for (var j = 0; j < verdictStr.length; j++) {
            if (view[i + j] !== verdictStr.charCodeAt(j)) {
                found = false;
                break;
            }
        }
        if (found) {
            console.log("[FOUND] 'verdict-wrap-aead-key/v1' at offset " + hex(i));
            break;
        }
    }

    // Search for high-entropy blocks that could be encrypted keys
    // Look for 32-byte or 64-byte blocks with high entropy
    console.log("[SCAN] Searching for high-entropy data blocks...");
    var highEntropy = [];
    for (var i = 0; i < view.length - 64; i += 4) {
        var unique = new Set();
        for (var j = 0; j < 64; j++) {
            unique.add(view[i + j]);
        }
        if (unique.size >= 45) {
            // Check if it's in a data section (not code)
            var hex = "";
            for (var j = 0; j < 64; j++) {
                hex += ("0" + view[i + j].toString(16)).slice(-2);
            }
            // Skip known patterns
            if (!hex.startsWith("00010203") && hex.indexOf("ffffff") === -1) {
                highEntropy.push({offset: i, hex: hex});
            }
        }
    }

    console.log("[SCAN] Found " + highEntropy.length + " high-entropy blocks");
    for (var i = 0; i < Math.min(highEntropy.length, 20); i++) {
        console.log("[ENTROPY] " + hex(highEntropy[i].offset) + ": " + highEntropy[i].hex.substring(0, 64) + "...");
    }

    // Search for 128-char hex strings (potential API keys)
    console.log("[SCAN] Searching for hex key patterns...");
    var hexPattern = /^[0-9a-f]{128}$/;
    for (var i = 0; i < view.length - 128; i++) {
        var str = "";
        var valid = true;
        for (var j = 0; j < 128; j++) {
            var c = view[i + j];
            if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102)) { // 0-9, a-f
                str += String.fromCharCode(c);
            } else {
                valid = false;
                break;
            }
        }
        if (valid && str.length === 128) {
            console.log("[HEX128] at " + hex(i) + ": " + str);
        }
    }

    // Search for 64-byte blocks that look like keys
    console.log("[SCAN] Searching for 64-byte key patterns...");
    for (var i = 0; i < view.length - 64; i++) {
        var hex = "";
        for (var j = 0; j < 64; j++) {
            hex += ("0" + view[i + j].toString(16)).slice(-2);
        }
        // Check if it looks like a key (mixed case hex, not sequential)
        if (hex.match(/^[0-9a-f]{128}$/) && !hex.startsWith("00010203")) {
            // Check entropy
            var unique = new Set();
            for (var j = 0; j < 128; j++) {
                unique.add(hex[j]);
            }
            if (unique.size >= 10) {
                console.log("[KEY64] at " + hex(i) + ": " + hex);
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
                    z05Addr = fnPtr;
                    console.log("[FOUND] _z05 at " + fnPtr);

                    // Disassemble the first 100 instructions
                    var code = fnPtr.readByteArray(256);
                    console.log("[DISASM] _z05 first 256 bytes:");
                    var hex = "";
                    for (var b = 0; b < 256; b++) {
                        hex += ("0" + new Uint8Array(code)[b].toString(16)).slice(-2);
                    }
                    console.log("[DISASM] " + hex);

                    // Hook _z05 with detailed tracing
                    Interceptor.attach(fnPtr, {
                        onEnter: function(args) {
                            console.log("[_z05] ===== CALLED =====");
                            // Read all 3 byte arrays
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

                            // Trace memory reads from the function
                            // Hook all memory reads in the function
                            try {
                                var funcSize = 1024; // Estimate
                                Interceptor.attach(fnPtr.add(0), {
                                    onEnter: function(args) {
                                        console.log("[_z05_TRACE] entered");
                                    },
                                    onLeave: function(retval) {
                                        console.log("[_z05_TRACE] returned " + retval);
                                    }
                                });
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

    // Also search for other functions that might contain the real key
    // Look for functions that reference "d-key" or "verdict" strings
    console.log("[SCAN] Searching for functions referencing key labels...");
    var dkeyAddr = coreLib.base.add(dkeyOffset);
    console.log("[SCAN] d-key string at " + dkeyAddr);

    // Scan for ADRP+ADD patterns that reference d-key
    // In x86_64, look for LEA instructions that reference the string
    for (var i = 0; i < view.length - 7; i++) {
        // LEA with RIP-relative addressing: 0x8d 0x05 <disp32>
        if (view[i] === 0x8d && view[i+1] === 0x05) {
            var disp = view[i+2] | (view[i+3] << 8) | (view[i+4] << 16) | (view[i+5] << 24);
            if (disp > 0x80000000) disp = disp - 0x100000000; // Signed
            var target = i + 6 + disp;
            if (target === dkeyOffset) {
                console.log("[FOUND] LEA to d-key at offset " + hex(i));
            }
        }
    }
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
