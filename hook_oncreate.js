"use strict";

// Hook Application.onCreate() to install NativeAuthBridge hooks
// BEFORE the app's initialization code runs

Java.performNow(function() {
    console.log("[JAVA] performNow");

    // Bypass Debug
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        Debug.waitForDebugger.implementation = function() {};
    } catch(e) {}

    // Bypass integrity
    try { Java.use("X5").i.implementation = function() { console.log("[BYPASS] X5.i"); return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { console.log("[BYPASS] G4.e"); return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { console.log("[BYPASS] F0.f"); return true; }; } catch(e) {}

    // Hook Application.onCreate
    try {
        var App = Java.use("nz.ac.auckland.se702.reverseai.ReverseAiApplication");
        App.onCreate.implementation = function() {
            console.log("[onCreate] BEFORE - installing NAB hooks...");

            // Install NativeAuthBridge hooks NOW (before onCreate body runs)
            try {
                var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");

                NAB._y01.implementation = function() {
                    try {
                        var r = this._y01();
                        console.log("[_y01] OK len=" + (r ? r.length : 0));
                        return r;
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
                        return Java.array("byte", new Array(32).fill(0));
                    }
                };

                NAB._y02.implementation = function() {
                    try {
                        var r = this._y02();
                        console.log("[_y02] OK: " + r);
                        return r;
                    } catch(e) {
                        console.log("[_y02] FAIL: " + e);
                        return 0;
                    }
                };

                NAB._y03.implementation = function() {
                    try {
                        var r = this._y03();
                        var hex = "";
                        if (r) for (var i = 0; i < r.length; i++) hex += ("0" + (r[i] & 0xFF).toString(16)).slice(-2);
                        console.log("[_y03] OK: " + hex + " len=" + (r ? r.length : 0));
                        return r;
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
                        return Java.array("byte", new Array(8).fill(0));
                    }
                };

                NAB._z05.implementation = function(a, b, c) {
                    var r = this._z05(a, b, c);
                    console.log("[_z05] " + r);
                    return r;
                };

                console.log("[onCreate] NAB hooks installed!");
            } catch(e) {
                console.log("[onCreate] NAB hook error: " + e);
            }

            // Now call the original onCreate
            console.log("[onCreate] Calling super.onCreate()...");
            this.onCreate();
            console.log("[onCreate] Done");
        };
        console.log("[HOOK] ReverseAiApplication.onCreate");
    } catch(e) { console.log("[ERR] onCreate: " + e); }

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
