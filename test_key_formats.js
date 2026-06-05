"use strict";
console.log("[INIT] Loading...");

Java.perform(function() {
    // Bypass
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Decrypted values from SharedPreferences
    var keyBlob = "d2c7b3a3fc4d247d01e188cbf404d47cc57af210e9f4ab7907c95fa361de5b70";
    var installToken = "0b5e11cfea67b7704877a1d57f07c75db1a4e6a3c18f8d1eb22ff7bf2ed4e898";
    var sharedKey = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7";

    // Test 1: Return keyBlob as the API key
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] Original: " + result);
            console.log("[_z05] Returning keyBlob: " + keyBlob);
            return keyBlob;
        };
        console.log("[HOOK] _z05 -> keyBlob");
    } catch(e) {}

    // Hook class v to see if auth succeeds
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        console.log("[HOOK] v.e");
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
});
