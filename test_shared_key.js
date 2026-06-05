"use strict";
console.log("[INIT] Loading...");

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Replace _z05 return with shared key (no Bearer)
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] Original: " + result);
            var sharedKey = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7";
            console.log("[_z05] Replaced: " + sharedKey);
            return sharedKey;
        };
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook _z06 to see auth response
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z06.implementation = function(a) {
            console.log("[_z06] called");
            this._z06(a);
        };
    } catch(e) {}

    // Hook class v.e to see API response
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] response: " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        v_cls.d.overload("r5", "java.util.Set", "boolean").implementation = function(a, b, c) {
            var r = this.d(a, b, c);
            console.log("[v.d] response: " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
});
