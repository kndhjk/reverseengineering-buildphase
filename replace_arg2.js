"use strict";

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var rnPtr = vtable.add(215 * Process.pointerSize).readPointer();

// Hook RegisterNatives to find _z05 native addr
Interceptor.attach(rnPtr, {
    onEnter: function(args) {
        var m = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = m.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var fn = entry.add(Process.pointerSize * 2).readPointer();
            if (name === "_z05") {
                console.log("[RN] _z05 at " + fn);
                // Hook native _z05 to log args
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
                                    }
                                } catch(e) {}
                            }
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
                        console.log("[NATIVE_z05] retval=" + retval);
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

    // Hook _z05 at Java level - replace arg2 (HMAC) with correct value
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            // Log original args
            if (a) {
                var hex = "";
                for (var i = 0; i < Math.min(a.length, 64); i++) hex += ("0" + (a[i] & 0xFF).toString(16)).slice(-2);
                console.log("[_z05_java] arg0(token) len=" + a.length + ": " + hex);
            } else {
                console.log("[_z05_java] arg0 = null");
            }
            if (b) {
                var hex = "";
                for (var i = 0; i < Math.min(b.length, 128); i++) hex += ("0" + (b[i] & 0xFF).toString(16)).slice(-2);
                console.log("[_z05_java] arg1(blob) len=" + b.length + ": " + hex);
            } else {
                console.log("[_z05_java] arg1 = null");
            }
            if (c) {
                var hex = "";
                for (var i = 0; i < Math.min(c.length, 32); i++) hex += ("0" + (c[i] & 0xFF).toString(16)).slice(-2);
                console.log("[_z05_java] arg2(hmac) len=" + c.length + ": " + hex);
            } else {
                console.log("[_z05_java] arg2 = null -> INJECTING HMAC!");
                // Create correct HMAC blob: ad48ad35df979c23
                c = Java.array("byte", [0xad, 0x48, 0xad, 0x35, 0xdf, 0x97, 0x9c, 0x23]);
                console.log("[_z05_java] Injected HMAC: ad48ad35df979c23");
            }

            var result = this._z05(a, b, c);
            console.log("[_z05_java] RETURNED: " + result);
            return result;
        };
        console.log("[HOOK] _z05 Java");
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

    console.log("[INIT] Done");
});
