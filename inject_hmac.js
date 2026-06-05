"use strict";

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var rnPtr = vtable.add(215 * Process.pointerSize).readPointer();

// Decrypted HMAC blob from SharedPreferences _p52
var HMAC_HEX = "ad48ad35df979c23";

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
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        var jniEnv = Java.vm.getEnv();

                        // Log original args
                        for (var a = 2; a < 5; a++) {
                            if (args[a].isNull()) {
                                console.log("[_z05] arg" + (a-2) + " = NULL");
                            } else {
                                try {
                                    var len = jniEnv.getArrayLength(args[a]);
                                    if (len > 0) {
                                        var arr = jniEnv.getByteArrayElements(args[a], null);
                                        var hex = "";
                                        for (var b = 0; b < Math.min(len, 128); b++) {
                                            hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                        }
                                        console.log("[_z05] arg" + (a-2) + " len=" + len + ": " + hex);
                                    }
                                } catch(e) {
                                    console.log("[_z05] arg" + (a-2) + " err=" + e);
                                }
                            }
                        }

                        // If arg2 (HMAC) is NULL, create a new byte array with correct HMAC
                        if (args[4].isNull()) {
                            console.log("[_z05] arg2 is NULL - injecting HMAC blob!");
                            try {
                                // Create a new byte array with the HMAC
                                var hmacBytes = [];
                                for (var h = 0; h < HMAC_HEX.length; h += 2) {
                                    hmacBytes.push(parseInt(HMAC_HEX.substr(h, 2), 16));
                                }
                                var jniEnv2 = Java.vm.getEnv();
                                var newArr = jniEnv2.newByteArray(hmacBytes.length);
                                // Use SetByteArrayRegion to copy data
                                var memArr = Memory.alloc(hmacBytes.length);
                                for (var h = 0; h < hmacBytes.length; h++) {
                                    Memory.writeU8(memArr.add(h), hmacBytes[h]);
                                }
                                // Call SetByteArrayRegion
                                var setRegion = new NativeFunction(
                                    jniEnv2.handle.readPointer()
                                        .add(78 * Process.pointerSize)  // SetByteArrayRegion at index 78
                                        .readPointer(),
                                    'void',
                                    ['pointer', 'pointer', 'int', 'int', 'pointer']
                                );
                                setRegion(jniEnv2.handle, newArr, 0, hmacBytes.length, memArr);
                                args[4] = newArr;
                                console.log("[_z05] Injected HMAC: " + HMAC_HEX);
                            } catch(e) {
                                console.log("[_z05] inject error: " + e);
                            }
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[_z05] retval=" + retval);
                    }
                });
            }

            if (name === "_z06") {
                console.log("[RN] _z06 at " + fn);
            }
        }
    }
});

// Java hooks
Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook _z05 at Java level
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var r = this._z05(a, b, c);
            console.log("[JAVA_z05] " + r);
            return r;
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

    console.log("[INIT] Done");
});
