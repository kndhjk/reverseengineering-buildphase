"use strict";
var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var newStringUTF = vtable.add(169 * Process.pointerSize).readPointer();
var z05Addr = null;
var inZ05 = false;

// Hook NewStringUTF to capture the string created by _z05
Interceptor.attach(newStringUTF, {
    onEnter: function(args) {
        if (inZ05) {
            try {
                var str = args[1].readUtf8String(512);
                console.log("[NewStringUTF in _z05] " + str);
            } catch(e) {
                console.log("[NewStringUTF in _z05] <cannot read>");
            }
        }
    }
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
                z05Addr = fnPtr;
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
