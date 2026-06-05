"use strict";
console.log("[INIT] Loading...");

Java.perform(function() {
    // Bypass
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook _z05 and replace return value
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] Original: " + result);
            
            // Replace with shared key (no Bearer prefix)
            var sharedKey = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7";
            console.log("[_z05] Replaced with: " + sharedKey);
            return sharedKey;
        };
        console.log("[HOOK] _z05 hooked");
    } catch(e) {
        console.log("[ERR] _z05: " + e);
    }

    console.log("[INIT] Done. Tap Generate...");
});
