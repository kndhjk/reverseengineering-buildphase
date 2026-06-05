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

                // Disassemble more of the function (2048 bytes)
                var code = fn.readByteArray(2048);
                var view = new Uint8Array(code);

                // Find ALL MOVABS instructions
                console.log("[DISASM] All MOVABS in _z05:");
                for (var j = 0; j < 2040; j++) {
                    if (view[j] === 0x48 && view[j+1] === 0xb8) {
                        var lo = 0, hi = 0;
                        for (var k = 0; k < 4; k++) {
                            lo += (view[j+2+k] << (k*8));
                            hi += (view[j+6+k] << (k*8));
                        }
                        var imm = lo + hi * 0x100000000;
                        console.log("[MOVABS +" + j + "] rax=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                    // MOVABS rcx
                    if (view[j] === 0x48 && view[j+1] === 0xb9) {
                        var lo = 0, hi = 0;
                        for (var k = 0; k < 4; k++) {
                            lo += (view[j+2+k] << (k*8));
                            hi += (view[j+6+k] << (k*8));
                        }
                        var imm = lo + hi * 0x100000000;
                        console.log("[MOVABS +" + j + "] rcx=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                }

                // Find all CALL instructions
                console.log("[DISASM] All CALL in _z05:");
                for (var j = 0; j < 2040; j++) {
                    if (view[j] === 0xe8) {
                        var disp = view[j+1] | (view[j+2] << 8) | (view[j+3] << 16) | (view[j+4] << 24);
                        if (disp > 0x80000000) disp -= 0x100000000;
                        var target = fn.add(j + 5 + disp);
                        console.log("[CALL +" + j + "] -> " + target);
                    }
                    // CALL reg (0xff /2)
                    if (view[j] === 0xff && (view[j+1] & 0x38) === 0x10) {
                        console.log("[CALL_REG +" + j + "] opcode=" + view[j].toString(16) + " " + view[j+1].toString(16));
                    }
                }

                // Find XOR operations
                console.log("[DISASM] XOR operations:");
                for (var j = 0; j < 2040; j++) {
                    // XOR r/m, r (0x31 or 0x33 or 0x35)
                    if (view[j] === 0x31 || view[j] === 0x33 || view[j] === 0x35) {
                        console.log("[XOR +" + j + "] " + view[j].toString(16) + " " + view[j+1].toString(16));
                    }
                    // PXOR xmm (0x66 0x0f 0xef)
                    if (view[j] === 0x66 && view[j+1] === 0x0f && view[j+2] === 0xef) {
                        console.log("[PXOR +" + j + "]");
                    }
                }

                // Find all RET instructions
                console.log("[DISASM] RET instructions:");
                for (var j = 0; j < 2040; j++) {
                    if (view[j] === 0xc3) {
                        console.log("[RET +" + j + "]");
                    }
                }

                // Hook _z05 to capture stack data after execution
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        console.log("[_z05] ENTER");
                        // Read SP
                        console.log("[_z05] SP=" + this.context.sp);
                    },
                    onLeave: function(retval) {
                        console.log("[_z05] retval=" + retval);
                        // Try to read the string from retval
                        try {
                            var jniEnv = Java.vm.getEnv();
                            var chars = jniEnv.getStringUtfChars(retval, null);
                            if (chars && !chars.isNull()) {
                                var str = chars.readUtf8String();
                                console.log("[_z05] string: " + str);
                            }
                        } catch(e) {
                            console.log("[_z05] read error: " + e);
                        }
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

    // Hook _z05 Java level with correct inputs
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            // Replace arg1 with decrypted blob (32 bytes)
            var decryptedBlob = Java.array("byte", [
                0xd2, 0xc7, 0xb3, 0xa3, 0xfc, 0x4d, 0x24, 0x7d,
                0x01, 0xe1, 0x88, 0xcb, 0xf4, 0x04, 0xd4, 0x7c,
                0xc5, 0x7a, 0xf2, 0x10, 0xe9, 0xf4, 0xab, 0x79,
                0x07, 0xc9, 0x5f, 0xa3, 0x61, 0xde, 0x5b, 0x70
            ]);
            var hmacBlob = Java.array("byte", [0xad, 0x48, 0xad, 0x35, 0xdf, 0x97, 0x9c, 0x23]);
            var result = this._z05(a, decryptedBlob, hmacBlob);
            console.log("[_z05_java] " + result);
            return result;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
