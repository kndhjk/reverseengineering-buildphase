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

                // Read first 1024 bytes of the function
                var code = fnPtr.readByteArray(1024);
                var view = new Uint8Array(code);

                // Find all LEA instructions (0x8d) that reference data
                for (var j = 0; j < 1020; j++) {
                    // LEA reg, [rip + disp32] = 0x48 0x8d 0x05 disp32
                    if (view[j] === 0x48 && view[j+1] === 0x8d && view[j+2] === 0x05) {
                        var disp = view[j+3] | (view[j+4] << 8) | (view[j+5] << 16) | (view[j+6] << 24);
                        if (disp > 0x80000000) disp -= 0x100000000;
                        var target = fnPtr.add(j + 7 + disp);
                        var targetData = target.readByteArray(128);
                        var tv = new Uint8Array(targetData);
                        var hex = "";
                        for (var k = 0; k < 128; k++) hex += ("0" + tv[k].toString(16)).slice(-2);
                        console.log("[LEA] +" + j + " -> " + target + " : " + hex.substring(0, 64) + "...");
                    }
                    // MOVABS rax, imm64 = 0x48 0xb8 imm64
                    if (view[j] === 0x48 && view[j+1] === 0xb8) {
                        var imm = 0;
                        for (var k = 0; k < 8; k++) imm += (view[j+2+k] << (k*8));
                        console.log("[MOVABS] +" + j + " rax=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                }

                // Hook the function to trace execution
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z05] ENTER");
                        var jniEnv = Java.vm.getEnv();
                        for (var a = 2; a < 5; a++) {
                            try {
                                var len = jniEnv.getArrayLength(args[a]);
                                var arr = jniEnv.getByteArrayElements(args[a], null);
                                if (arr && len > 0) {
                                    var hex = "";
                                    for (var b = 0; b < Math.min(len, 128); b++) hex += ("0" + Memory.readU8(arr.add(b)).toString(16)).slice(-2);
                                    console.log("[_z05] arg" + (a-2) + " len=" + len + " : " + hex);
                                }
                            } catch(e) {}
                        }
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
