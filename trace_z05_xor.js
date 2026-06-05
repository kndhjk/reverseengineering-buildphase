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

                // Hook the function at +976 (likely the key derivation function)
                var innerFn = fn.add(976);
                console.log("[HOOK] Inner function at " + innerFn);

                Interceptor.attach(innerFn, {
                    onEnter: function(args) {
                        console.log("[INNER] ENTER");
                        // Read args
                        for (var a = 0; a < 4; a++) {
                            try {
                                if (!args[a].isNull()) {
                                    var bytes = args[a].readByteArray(64);
                                    var view = new Uint8Array(bytes);
                                    var hex = "";
                                    for (var b = 0; b < 64; b++) hex += ("0" + view[b].toString(16)).slice(-2);
                                    console.log("[INNER] arg" + a + " = " + hex);
                                }
                            } catch(e) {}
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[INNER] retval=" + retval);
                    }
                });

                // Hook the function at +739 (within core lib)
                var fn739 = fn.add(739);
                console.log("[HOOK] Function at +739: " + fn739);
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

                // Hook _z05 itself to capture the XOR buffer on stack
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        console.log("[_z05] ENTER");
                        // Read arg0 and arg1
                        try {
                            var jniEnv = Java.vm.getEnv();
                            for (var a = 2; a < 4; a++) {
                                if (args[a].isNull()) continue;
                                var len = jniEnv.getArrayLength(args[a]);
                                if (len > 0) {
                                    var arr = jniEnv.getByteArrayElements(args[a], null);
                                    var hex = "";
                                    for (var b = 0; b < Math.min(len, 128); b++) {
                                        hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                    }
                                    console.log("[_z05] arg" + (a-2) + " len=" + len + ": " + hex);
                                }
                            }
                        } catch(e) {}
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
    console.log("[INIT] Done");
});
