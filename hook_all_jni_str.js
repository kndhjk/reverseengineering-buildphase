"use strict";
var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var inZ05 = false;

// Hook ALL JNI string functions
var nsuIdx = 169; // NewStringUTF
var nsIdx = 168;  // NewString

[nsuIdx, nsIdx].forEach(function(idx) {
    var fnPtr = vtable.add(idx * Process.pointerSize).readPointer();
    Interceptor.attach(fnPtr, {
        onEnter: function(args) {
            if (inZ05) {
                try {
                    var str = args[1].readUtf8String(512);
                    console.log("[JNI_STR idx=" + idx + " in _z05] " + str);
                } catch(e) {
                    try {
                        var str = args[1].readUtf16String(512);
                        console.log("[JNI_STR idx=" + idx + " in _z05 UTF16] " + str);
                    } catch(e2) {
                        console.log("[JNI_STR idx=" + idx + " in _z05] <cannot read>");
                    }
                }
            }
        }
    });
});

// Hook GetStringUTFChars (idx 170) and GetStringChars (idx 166)
[170, 166].forEach(function(idx) {
    var fnPtr = vtable.add(idx * Process.pointerSize).readPointer();
    Interceptor.attach(fnPtr, {
        onEnter: function(args) {
            if (inZ05) {
                console.log("[JNI_GET_STR idx=" + idx + " in _z05] called");
            }
        },
        onLeave: function(retval) {
            if (inZ05 && !retval.isNull()) {
                try {
                    var str = retval.readUtf8String(512);
                    console.log("[JNI_GET_STR idx=" + idx + " result] " + str);
                } catch(e) {}
            }
        }
    });
});

// Hook RegisterNatives to find _z05
Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
        var methods = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = methods.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
            if (name === "_z05") {
                console.log("[FOUND] _z05 at " + fnPtr);
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        inZ05 = true;
                        console.log("[_z05] ENTER");
                    },
                    onLeave: function(retval) {
                        inZ05 = false;
                        console.log("[_z05] LEAVE retval=" + retval);
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
});
console.log("[INIT] Done");
