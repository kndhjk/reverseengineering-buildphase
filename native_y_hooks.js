"use strict";

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var rnPtr = vtable.add(215 * Process.pointerSize).readPointer();

Interceptor.attach(rnPtr, {
    onEnter: function(args) {
        var m = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = m.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var sig = entry.add(Process.pointerSize).readPointer().readUtf8String();
            var fn = entry.add(Process.pointerSize * 2).readPointer();
            console.log("[RN] " + name + " " + sig + " -> " + fn);

            if (name === "_y01" || name === "_y02" || name === "_y03") {
                (function(nm) {
                    Interceptor.attach(fn, {
                        onEnter: function(args) {
                            console.log("[NATIVE_" + nm + "] ENTER");
                        },
                        onLeave: function(retval) {
                            console.log("[NATIVE_" + nm + "] retval=" + retval);
                        }
                    });
                    console.log("[HOOK] Native " + nm + " at " + fn);
                })(name);
            }

            if (name === "_z05") {
                console.log("[HOOK] Native _z05 at " + fn);
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        console.log("[NATIVE_z05] ENTER");
                        try {
                            var jniEnv = Java.vm.getEnv();
                            for (var a = 2; a < 5; a++) {
                                if (args[a].isNull()) {
                                    console.log("[NATIVE_z05] arg" + (a-2) + " = NULL");
                                    continue;
                                }
                                try {
                                    var len = jniEnv.getArrayLength(args[a]);
                                    if (len > 0) {
                                        var arr = jniEnv.getByteArrayElements(args[a], null);
                                        var hex = "";
                                        for (var b = 0; b < Math.min(len, 128); b++) {
                                            hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                        }
                                        console.log("[NATIVE_z05] arg" + (a-2) + " len=" + len + ": " + hex);
                                    } else {
                                        console.log("[NATIVE_z05] arg" + (a-2) + " len=0");
                                    }
                                } catch(e) {
                                    console.log("[NATIVE_z05] arg" + (a-2) + " err=" + e);
                                }
                            }
                        } catch(e) {
                            console.log("[NATIVE_z05] input err=" + e);
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[NATIVE_z05] LEAVE retval=" + retval);
                    }
                });
            }
        }
    }
});

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    setTimeout(function() {
        console.log("[INIT] Installing Java hooks...");

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
                    try {
                        var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                        var sp = ctx.getSharedPreferences("v_p1", 0);
                        var vitm = sp.getLong("vitm", 0);
                        console.log("[_y02] SP fallback: " + vitm);
                        return vitm;
                    } catch(e2) {}
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

            console.log("[HOOK] Java NAB hooks installed");
        } catch(e) { console.log("[ERR] NAB: " + e); }

        try {
            var SP = Java.use("android.app.SharedPreferencesImpl");
            SP.getString.implementation = function(key, def) {
                var val = this.getString(key, def);
                console.log("[SP] " + key + " = " + (val ? val.substring(0, 100) : "null"));
                return val;
            };
        } catch(e) {}

        console.log("[INIT] Done. Tap Generate...");
    }, 5000);
});
