"use strict";

var fullHmac = null;

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook Mac.doFinal to capture FULL HMAC (32 bytes, not truncated to 8)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            if (result.length >= 32) {
                var hex = "";
                for (var i = 0; i < result.length; i++) hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
                console.log("[MAC_FULL] algo=" + this.getAlgorithm() + " len=" + result.length + " hex=" + hex);
                fullHmac = result;
            }
            return result;
        };
        Mac.init.overload("java.security.Key").implementation = function(key) {
            try {
                var kb = key.getEncoded();
                var hex = "";
                for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                console.log("[MAC_KEY] algo=" + this.getAlgorithm() + " key=" + hex);
            } catch(e2) {}
            return this.init(key);
        };
        console.log("[HOOK] Mac");
    } catch(e) { console.log("[ERR] Mac: " + e); }

    // Hook F0.a to capture the truncated HMAC
    try {
        var F0 = Java.use("F0");
        F0.a.overload("[B", "long").implementation = function(key, ts) {
            var result = this.a(key, ts);
            var hex = "";
            if (result) for (var i = 0; i < result.length; i++) hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
            console.log("[F0.a] key_len=" + key.length + " ts=" + ts + " result=" + hex + " len=" + (result ? result.length : 0));
            return result;
        };
        console.log("[HOOK] F0.a");
    } catch(e) { console.log("[ERR] F0.a: " + e); }

    // Hook _z05 - replace arg2 with full 32-byte HMAC when available
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            // Replace arg1 with decrypted blob (32 bytes)
            var decryptedBlob = Java.array("byte", [
                0xd2, 0xc7, 0xb3, 0xa3, 0xfc, 0x4d, 0x24, 0x7d,
                0x01, 0xe1, 0x88, 0xcb, 0xf4, 0x04, 0xd4, 0x7c,
                0xc5, 0x7a, 0xf2, 0x10, 0xe9, 0xf4, 0xab, 0x79,
                0x07, 0xc9, 0x5f, 0xa3, 0x61, 0xde, 0x5b, 0x70
            ]);

            // Use full HMAC if available, otherwise use 32-byte padded
            var hmac32;
            if (fullHmac && fullHmac.length >= 32) {
                var arr = [];
                for (var i = 0; i < 32; i++) arr.push(fullHmac[i] & 0xFF);
                hmac32 = Java.array("byte", arr);
                console.log("[_z05] Using FULL HMAC (32 bytes)");
            } else {
                // Pad the 8-byte HMAC to 32 bytes with zeros
                hmac32 = Java.array("byte", [
                    0xad, 0x48, 0xad, 0x35, 0xdf, 0x97, 0x9c, 0x23,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0
                ]);
                console.log("[_z05] Using padded HMAC (8 bytes + 24 zeros)");
            }

            var result = this._z05(a, decryptedBlob, hmac32);
            console.log("[_z05] " + result);
            return result;
        };
        console.log("[HOOK] _z05");
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook v.a
    try {
        var v_cls = Java.use("v");
        v_cls.a.overload("v", "H1", "java.lang.String").implementation = function(self, h1, s) {
            console.log("[v.a] key=" + (s ? s.substring(0, 200) : "null"));
            return this.a(self, h1, s);
        };
    } catch(e) {}

    // Hook v.c
    try {
        var v_cls = Java.use("v");
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(p7, s, h1) {
            console.log("[v.c] " + (s ? s.substring(0, 200) : "null"));
            return this.c(p7, s, h1);
        };
    } catch(e) {}

    // Hook v.e
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val.substring(0, 100) : "null"));
            return val;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
