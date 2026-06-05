"use strict";
var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var z05Found = false;

Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
        var methods = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = methods.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();

            if (name === "_z05" && !z05Found) {
                z05Found = true;
                console.log("[FOUND] _z05 at " + fnPtr);

                // Read function code and find ALL MOVABS constants
                var code = fnPtr.readByteArray(2048);
                var view = new Uint8Array(code);
                for (var j = 0; j < 2040; j++) {
                    if (view[j] === 0x48 && view[j+1] === 0xb8) {
                        var lo = 0, hi = 0;
                        for (var k = 0; k < 4; k++) { lo += (view[j+2+k] << (k*8)); hi += (view[j+6+k] << (k*8)); }
                        var imm = lo + hi * 0x100000000;
                        console.log("[MOVABS +" + j + "] rax=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                    if (view[j] === 0x48 && view[j+1] === 0xb9) {
                        var lo = 0, hi = 0;
                        for (var k = 0; k < 4; k++) { lo += (view[j+2+k] << (k*8)); hi += (view[j+6+k] << (k*8)); }
                        var imm = lo + hi * 0x100000000;
                        console.log("[MOVABS +" + j + "] rcx=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                }

                // Hook _z05 safely (only read non-null arrays)
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z05] ENTER");
                        try {
                            var jniEnv = Java.vm.getEnv();
                            for (var a = 2; a < 5; a++) {
                                try {
                                    if (args[a].isNull()) { console.log("[_z05] arg" + (a-2) + " = NULL"); continue; }
                                    var len = jniEnv.getArrayLength(args[a]);
                                    if (len === 0) { console.log("[_z05] arg" + (a-2) + " len=0"); continue; }
                                    var arr = jniEnv.getByteArrayElements(args[a], null);
                                    if (arr && !arr.isNull()) {
                                        var hex = "";
                                        for (var b = 0; b < Math.min(len, 128); b++) hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                        console.log("[_z05] arg" + (a-2) + " len=" + len + " : " + hex);
                                    }
                                } catch(e) { console.log("[_z05] arg" + (a-2) + " err=" + e); }
                            }
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
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
