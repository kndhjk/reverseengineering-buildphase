"use strict";
// Strategy: hook _z05 at native level via RegisterNatives,
// then call it with CORRECT inputs (from SharedPreferences decrypted values)
// to see if it produces a DIFFERENT (non-decoy) key.

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var z05FnPtr = null;

Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
        var methods = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = methods.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
            if (name === "_z05") {
                z05FnPtr = fnPtr;
                console.log("[FOUND] _z05 at " + fnPtr);
            }
            if (name === "_z06") {
                console.log("[FOUND] _z06 at " + fnPtr);
            }
        }
    }
});

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Wait a bit for RegisterNatives to fire
    setTimeout(function() {
        console.log("[INIT] RegisterNatives done, z05FnPtr=" + z05FnPtr);

        // Known correct values from SharedPreferences (decrypted)
        var installTokenHex = "0b5e11cfea67b7704877a1d57f07c75db1a4e6a3c18f8d1eb22ff7bf2ed4e898";
        var keyBlobHex = "d2c7b3a3fc4d247d01e188cbf404d47cc57af210e9f4ab7907c95fa361de5b70";
        var hmacHex = "ad48ad35df979c23";

        // Convert hex to byte arrays
        function hexToBytes(hex) {
            var bytes = [];
            for (var i = 0; i < hex.length; i += 2) {
                bytes.push(parseInt(hex.substr(i, 2), 16));
            }
            return bytes;
        }

        var tokenBytes = hexToBytes(installTokenHex);
        var keyBlobBytes = hexToBytes(keyBlobHex);
        var hmacBytes = hexToBytes(hmacHex);

        console.log("[DATA] token len=" + tokenBytes.length);
        console.log("[DATA] keyBlob len=" + keyBlobBytes.length);
        console.log("[DATA] hmac len=" + hmacBytes.length);

        // Create Java byte arrays
        var jToken = Java.array("byte", tokenBytes);
        var jKeyBlob = Java.array("byte", keyBlobBytes);
        var jHmac = Java.array("byte", hmacBytes);

        // Call _z05 with correct inputs
        try {
            var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
            console.log("[CALL] Calling _z05 with correct inputs...");
            var result = NAB._z05(jToken, jKeyBlob, jHmac);
            console.log("[RESULT] _z05 returned: " + result);
        } catch(e) {
            console.log("[ERR] _z05 call: " + e);
        }

        // Also try with empty inputs to see if it changes
        try {
            var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
            var empty = Java.array("byte", []);
            console.log("[CALL] Calling _z05 with empty inputs...");
            var result2 = NAB._z05(empty, empty, empty);
            console.log("[RESULT] _z05(empty) returned: " + result2);
        } catch(e) {
            console.log("[ERR] _z05(empty): " + e);
        }

        // Try with just the key blob
        try {
            var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
            var empty = Java.array("byte", []);
            console.log("[CALL] Calling _z05 with just keyBlob...");
            var result3 = NAB._z05(empty, jKeyBlob, empty);
            console.log("[RESULT] _z05(keyBlob) returned: " + result3);
        } catch(e) {
            console.log("[ERR] _z05(keyBlob): " + e);
        }

        // Try with full 128-byte key blob (with IV prefix)
        try {
            var fullKeyBlobHex = "00000000000000000000000000000000117c3a309476becd5d064d4206bff43ada68bd71fbcc6eee821ed68e41d83f855ebbfb5a9be392c7a9cc77ffd36c6563f6da4619d944b4e35ae3fb40731b8e18b58d62053c0e431925a2ed723815842fcc6fb232b227b85c827bde038a37fdb2a23c39738cb8f880d4ad458674eef145";
            var fullBytes = hexToBytes(fullKeyBlobHex);
            var jFull = Java.array("byte", fullBytes);
            console.log("[CALL] Calling _z05 with full 128-byte keyBlob...");
            var result4 = NAB._z05(jToken, jFull, jHmac);
            console.log("[RESULT] _z05(full) returned: " + result4);
        } catch(e) {
            console.log("[ERR] _z05(full): " + e);
        }

    }, 3000);

    console.log("[INIT] Done");
});
