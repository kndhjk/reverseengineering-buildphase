"use strict";
Java.perform(function() {
    console.log("[INIT] Loading integrity bypass...");

    // Bypass Debug
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        Debug.waitForDebugger.implementation = function() {};
        console.log("[BYPASS] Debug");
    } catch(e) {}

    // Bypass X5.i
    try {
        var X5 = Java.use("X5");
        X5.i.implementation = function() {
            console.log("[BYPASS] X5.i() -> true");
            return true;
        };
        console.log("[HOOK] X5.i");
    } catch(e) { console.log("[ERR] X5.i: " + e); }

    // Bypass G4.e
    try {
        var G4 = Java.use("G4");
        G4.e.implementation = function() {
            console.log("[BYPASS] G4.e() -> true");
            return true;
        };
        console.log("[HOOK] G4.e");
    } catch(e) { console.log("[ERR] G4.e: " + e); }

    // Bypass F0.f
    try {
        var F0 = Java.use("F0");
        F0.f.implementation = function() {
            console.log("[BYPASS] F0.f() -> true");
            return true;
        };
        console.log("[HOOK] F0.f");
    } catch(e) { console.log("[ERR] F0.f: " + e); }

    // Hook _y01 with exception fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y01.implementation = function() {
            try {
                var result = this._y01();
                console.log("[_y01] success, len=" + (result ? result.length : 0));
                return result;
            } catch(e) {
                console.log("[_y01] exception: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var vit = sp.getString("vit", null);
                    if (vit) {
                        var decoded = Java.use("android.util.Base64").decode(vit, 2);
                        console.log("[_y01] fallback from SP, len=" + decoded.length);
                        return decoded;
                    }
                } catch(e2) { console.log("[_y01] fallback err: " + e2); }
                throw e;
            }
        };
        console.log("[HOOK] _y01");
    } catch(e) { console.log("[ERR] _y01: " + e); }

    // Hook _y02 with exception fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y02.implementation = function() {
            try {
                var result = this._y02();
                console.log("[_y02] success: " + result);
                return result;
            } catch(e) {
                console.log("[_y02] exception: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var vitm = sp.getLong("vitm", 0);
                    console.log("[_y02] fallback: vitm=" + vitm);
                    return vitm;
                } catch(e2) { console.log("[_y02] fallback err: " + e2); }
                throw e;
            }
        };
        console.log("[HOOK] _y02");
    } catch(e) { console.log("[ERR] _y02: " + e); }

    // Hook _y03 with exception fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y03.implementation = function() {
            try {
                var result = this._y03();
                var hex = "";
                if (result) {
                    for (var i = 0; i < result.length; i++) hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
                }
                console.log("[_y03] success: " + hex + " len=" + (result ? result.length : 0));
                return result;
            } catch(e) {
                console.log("[_y03] exception: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var p52 = sp.getString("_p52", null);
                    if (p52) {
                        var decoded = Java.use("android.util.Base64").decode(p52, 2);
                        var hex = "";
                        for (var i = 0; i < decoded.length; i++) hex += ("0" + (decoded[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[_y03] fallback from SP: " + hex + " len=" + decoded.length);
                        return decoded;
                    }
                } catch(e2) { console.log("[_y03] fallback err: " + e2); }
                throw e;
            }
        };
        console.log("[HOOK] _y03");
    } catch(e) { console.log("[ERR] _y03: " + e); }

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
        console.log("[HOOK] _z05");
    } catch(e) { console.log("[ERR] _z05: " + e); }

    // Hook _z06
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z06.implementation = function(a) {
            console.log("[_z06] called");
            return this._z06(a);
        };
        console.log("[HOOK] _z06");
    } catch(e) { console.log("[ERR] _z06: " + e); }

    // Hook v.a
    try {
        var v_cls = Java.use("v");
        v_cls.a.overload("v", "H1", "java.lang.String").implementation = function(self, h1, s) {
            console.log("[v.a] key=" + (s ? s.substring(0, 200) : "null"));
            return this.a(self, h1, s);
        };
        console.log("[HOOK] v.a");
    } catch(e) { console.log("[ERR] v.a: " + e); }

    // Hook v.c
    try {
        var v_cls = Java.use("v");
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(p7, s, h1) {
            console.log("[v.c] " + (s ? s.substring(0, 200) : "null"));
            return this.c(p7, s, h1);
        };
        console.log("[HOOK] v.c");
    } catch(e) { console.log("[ERR] v.c: " + e); }

    // Hook v.e
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        console.log("[HOOK] v.e");
    } catch(e) { console.log("[ERR] v.e: " + e); }

    // Hook X5.f
    try {
        var X5 = Java.use("X5");
        X5.f.implementation = function() {
            var r = this.f();
            var hex = "";
            if (r) for (var i = 0; i < Math.min(r.length, 64); i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
            console.log("[X5.f] " + hex + " len=" + (r ? r.length : 0));
            return r;
        };
        console.log("[HOOK] X5.f");
    } catch(e) { console.log("[ERR] X5.f: " + e); }

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] getString(" + key + ") = " + (val ? val.substring(0, 100) : "null"));
            return val;
        };
        console.log("[HOOK] SP");
    } catch(e) { console.log("[ERR] SP: " + e); }

    console.log("[INIT] All hooks installed. Tap Generate...");
});
