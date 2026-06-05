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
            var fn = entry.add(Process.pointerSize * 2).readPointer();

            if (name === "_z05") {
                console.log("[FOUND] _z05 at " + fn);

                // Hook the inner function at offset +976
                var innerFn = fn.add(976);
                console.log("[HOOK] Inner fn at " + innerFn);

                var callCount = 0;
                Interceptor.attach(innerFn, {
                    onEnter: function(args) {
                        callCount++;
                        console.log("[INNER] call #" + callCount);
                        // Read all args
                        for (var a = 0; a < 6; a++) {
                            try {
                                if (args[a].isNull()) {
                                    console.log("[INNER] arg" + a + " = NULL");
                                    continue;
                                }
                                // Try to read as pointer
                                var ptr = args[a];
                                console.log("[INNER] arg" + a + " = " + ptr);

                                // Try to read bytes at this pointer
                                try {
                                    var bytes = ptr.readByteArray(64);
                                    var view = new Uint8Array(bytes);
                                    var hex = "";
                                    for (var b = 0; b < 64; b++) hex += ("0" + view[b].toString(16)).slice(-2);
                                    console.log("[INNER] arg" + a + " bytes: " + hex);
                                } catch(e2) {}
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[INNER] retval=" + retval);
                        // Try to read bytes at retval
                        try {
                            if (!retval.isNull()) {
                                var bytes = retval.readByteArray(64);
                                var view = new Uint8Array(bytes);
                                var hex = "";
                                for (var b = 0; b < 64; b++) hex += ("0" + view[b].toString(16)).slice(-2);
                                console.log("[INNER] retval bytes: " + hex);
                            }
                        } catch(e) {}
                    }
                });

                // Also hook the function at +739
                var fn739 = fn.add(739);
                console.log("[HOOK] fn+739 at " + fn739);
                Interceptor.attach(fn739, {
                    onEnter: function(args) {
                        console.log("[FN739] ENTER");
                        for (var a = 0; a < 4; a++) {
                            try {
                                if (!args[a].isNull()) {
                                    var bytes = args[a].readByteArray(32);
                                    var view = new Uint8Array(bytes);
                                    var hex = "";
                                    for (var b = 0; b < 32; b++) hex += ("0" + view[b].toString(16)).slice(-2);
                                    console.log("[FN739] arg" + a + " = " + hex);
                                }
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[FN739] retval=" + retval);
                    }
                });

                // Hook the function at +1188 (0x772ef2625360)
                var fn1188 = fn.add(1188);
                console.log("[HOOK] fn+1188 at " + fn1188);
                Interceptor.attach(fn1188, {
                    onEnter: function(args) {
                        console.log("[FN1188] ENTER");
                        for (var a = 0; a < 4; a++) {
                            try {
                                if (!args[a].isNull()) {
                                    var bytes = args[a].readByteArray(32);
                                    var view = new Uint8Array(bytes);
                                    var hex = "";
                                    for (var b = 0; b < 32; b++) hex += ("0" + view[b].toString(16)).slice(-2);
                                    console.log("[FN1188] arg" + a + " = " + hex);
                                }
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[FN1188] retval=" + retval);
                    }
                });

                // Hook _z05 itself
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        console.log("[_z05] ENTER");
                    },
                    onLeave: function(retval) {
                        console.log("[_z05] retval=" + retval);
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

    // Replace _z05 args with correct values
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var decryptedBlob = Java.array("byte", [
                0xd2, 0xc7, 0xb3, 0xa3, 0xfc, 0x4d, 0x24, 0x7d,
                0x01, 0xe1, 0x88, 0xcb, 0xf4, 0x04, 0xd4, 0x7c,
                0xc5, 0x7a, 0xf2, 0x10, 0xe9, 0xf4, 0xab, 0x79,
                0x07, 0xc9, 0x5f, 0xa3, 0x61, 0xde, 0x5b, 0x70
            ]);
            var hmac32 = Java.array("byte", [
                0xad, 0x48, 0xad, 0x35, 0xdf, 0x97, 0x9c, 0x23,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]);
            var result = this._z05(a, decryptedBlob, hmac32);
            console.log("[_z05_java] " + result);
            return result;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
