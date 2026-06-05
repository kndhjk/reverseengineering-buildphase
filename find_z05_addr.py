#!/usr/bin/env python3
"""Find _z05 address by scanning memory for JNINativeMethod table."""
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

console.log("[INIT] Finding _z05...");

var coreLib = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("reverseai-core") !== -1) {
        coreLib = mods[i];
        break;
    }
}

if (coreLib) {
    console.log("[CORE] " + coreLib.name + " at " + coreLib.base);

    // The JNI signature for _z05 is ([B[B[B)Ljava/lang/String;
    // Search for this signature in the library
    var sig = "([B[B[B)Ljava/lang/String;";
    var sigBytes = [];
    for (var i = 0; i < sig.length; i++) {
        sigBytes.push(sig.charCodeAt(i));
    }

    // Search in the library memory
    var libData = coreLib.base.readByteArray(coreLib.size);
    var view = new Uint8Array(libData);

    var sigPos = -1;
    for (var i = 0; i < view.length - sig.length; i++) {
        var found = true;
        for (var j = 0; j < sig.length; j++) {
            if (view[i + j] !== sigBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            sigPos = i;
            console.log("[FOUND] Signature at offset " + hex(i) + " (addr " + hex(coreLib.base.add(i)) + ")");
            break;
        }
    }

    if (sigPos !== -1) {
        // Now search for a pointer to this signature
        var sigAddr = coreLib.base.add(sigPos);
        console.log("[SEARCH] Looking for pointer to " + sigAddr);

        // Search in all writable/readable memory
        // The JNINativeMethod table should be in .data or .bss
        // Let's search the library's data sections

        // First, find all segments
        // Parse ELF header
        var e_phoff = view[32] | (view[33] << 8) | (view[34] << 16) | (view[35] << 24) |
                     (view[36] << 32) | (view[37] << 40) | (view[38] << 48) | (view[39] << 56);
        var e_phnum = view[56] | (view[57] << 8);

        var segments = [];
        for (var i = 0; i < e_phnum; i++) {
            var off = e_phoff + i * 56;
            var p_type = view[off] | (view[off+1] << 8) | (view[off+2] << 16) | (view[off+3] << 24);
            var p_offset = view[off+8] | (view[off+9] << 8) | (view[off+10] << 16) | (view[off+11] << 24) |
                          (view[off+12] << 32) | (view[off+13] << 40) | (view[off+14] << 48) | (view[off+15] << 56);
            var p_vaddr = view[off+16] | (view[off+17] << 8) | (view[off+18] << 16) | (view[off+19] << 24) |
                         (view[off+20] << 32) | (view[off+21] << 40) | (view[off+22] << 48) | (view[off+23] << 56);
            var p_filesz = view[off+32] | (view[off+33] << 8) | (view[off+34] << 16) | (view[off+35] << 24) |
                          (view[off+36] << 32) | (view[off+37] << 40) | (view[off+38] << 48) | (view[off+39] << 56);

            if (p_type === 1) { // PT_LOAD
                segments.push({vaddr: p_vaddr, offset: p_offset, filesz: p_filesz});
            }
        }

        // Convert signature offset to vaddr
        var sigVaddr = null;
        for (var i = 0; i < segments.length; i++) {
            var seg = segments[i];
            if (seg.offset <= sigPos && sigPos < seg.offset + seg.filesz) {
                sigVaddr = sigPos - seg.offset + seg.vaddr;
                break;
            }
        }

        if (sigVaddr !== null) {
            console.log("[VADDR] Signature vaddr: " + hex(sigVaddr));

            // Search for pointer to signature in the library
            var ptrBytes = [];
            for (var i = 0; i < 8; i++) {
                ptrBytes.push((sigVaddr >> (i * 8)) & 0xFF);
            }

            for (var i = 0; i < view.length - 24; i += 8) {
                if (view[i] === ptrBytes[0] && view[i+1] === ptrBytes[1] &&
                    view[i+2] === ptrBytes[2] && view[i+3] === ptrBytes[3] &&
                    view[i+4] === ptrBytes[4] && view[i+5] === ptrBytes[5] &&
                    view[i+6] === ptrBytes[6] && view[i+7] === ptrBytes[7]) {

                    // Found pointer to signature
                    // Check if there's a name pointer before it
                    var namePtr = 0;
                    for (var j = 0; j < 8; j++) {
                        namePtr |= (view[i-8+j] << (j * 8));
                    }

                    // And a function pointer after it
                    var fnPtr = 0;
                    for (var j = 0; j < 8; j++) {
                        fnPtr |= (view[i+8+j] << (j * 8));
                    }

                    console.log("[TABLE] Found at offset " + hex(i));
                    console.log("[TABLE] namePtr: " + hex(namePtr));
                    console.log("[TABLE] sigPtr: " + hex(sigVaddr));
                    console.log("[TABLE] fnPtr: " + hex(fnPtr));

                    // Read name string
                    var nameOff = null;
                    for (var s = 0; s < segments.length; s++) {
                        var seg = segments[s];
                        if (seg.vaddr <= namePtr && namePtr < seg.vaddr + seg.filesz) {
                            nameOff = namePtr - seg.vaddr + seg.offset;
                            break;
                        }
                    }

                    if (nameOff !== null) {
                        var nameStr = "";
                        for (var j = nameOff; j < view.length && view[j] !== 0; j++) {
                            nameStr += String.fromCharCode(view[j]);
                        }
                        console.log("[TABLE] name: " + nameStr);
                    }

                    // The function pointer is the _z05 native implementation
                    console.log("[RESULT] _z05 native function at vaddr " + hex(fnPtr));

                    // Now hook this function
                    var fnAddr = ptr(fnPtr);
                    console.log("[HOOK] Hooking _z05 at " + fnAddr);

                    Interceptor.attach(fnAddr, {
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
