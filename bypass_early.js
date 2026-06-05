"use strict";

// Install hooks BEFORE Java.perform - at the native level
console.log("[INIT] Pre-Java hooks...");

// Hook the JNI_OnLoad of libreverseai-core.so to intercept RegisterNatives
var coreLib = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("reverseai-core") !== -1) {
        coreLib = mods[i];
        break;
    }
}

if (coreLib) {
    console.log("[CORE] Found: " + coreLib.name + " at " + coreLib.base);
}

// Now do Java.perform - this will run after the VM is ready
Java.perform(function() {
    console.log("[JAVA] Java.perform OK");

    // Bypass Debug immediately
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        Debug.waitForDebugger.implementation = function() {};
    } catch(e) {}

    // Bypass X5.i, G4.e, F0.f
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook _y01 with SP fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y01.implementation = function() {
            try {
                var result = this._y01();
                console.log("[_y01] OK len=" + (result ? result.length : 0));
                return result;
            } catch(e) {
                console.log("[_y01] FAIL: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var vit = sp.getString("vit", null);
                    if (vit) {
                        var decoded = Java.use("android.util.Base64").decode(vit, 2);
                        console.log("[_y01] SP fallback len=" + decoded.length);
                        return decoded;
                    }
                } catch(e2) {}
                // Return a dummy 32-byte array
                var dummy = Java.array("byte", new Array(32).fill(0));
                console.log("[_y01] dummy fallback");
                return dummy;
            }
        };
    } catch(e) {}

    // Hook _y02 with SP fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y02.implementation = function() {
            try {
                var result = this._y02();
                console.log("[_y02] OK: " + result);
                return result;
            } catch(e) {
                console.log("[_y02] FAIL: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var vitm = sp.getLong("vitm", 0);
                    console.log("[_y02] SP fallback: " + vitm);
                    return vitm;
                } catch(e2) {}
                console.log("[_y02] dummy fallback");
                return 0;
            }
        };
    } catch(e) {}

    // Hook _y03 with SP fallback
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._y03.implementation = function() {
            try {
                var result = this._y03();
                var hex = "";
                if (result) for (var i = 0; i < result.length; i++) hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
                console.log("[_y03] OK: " + hex + " len=" + (result ? result.length : 0));
                return result;
            } catch(e) {
                console.log("[_y03] FAIL: " + e);
                try {
                    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    var sp = ctx.getSharedPreferences("v_p1", 0);
                    var p52 = sp.getString("_p52", null);
                    if (p52) {
                        var decoded = Java.use("android.util.Base64").decode(p52, 2);
                        var hex = "";
                        for (var i = 0; i < decoded.length; i++) hex += ("0" + (decoded[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[_y03] SP fallback: " + hex + " len=" + decoded.length);
                        return decoded;
                    }
                } catch(e2) {}
                var dummy = Java.array("byte", new Array(8).fill(0));
                console.log("[_y03] dummy fallback");
                return dummy;
            }
        };
    } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

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

    console.log("[INIT] Done. Tap Generate...");
});
