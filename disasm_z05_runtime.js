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

            if (name === "_z05") {
                console.log("[FOUND] _z05 at " + fn);

                // Read first 1024 bytes of the function
                var code = fn.readByteArray(1024);
                var view = new Uint8Array(code);

                // Print as hex dump
                console.log("[CODE] First 256 bytes:");
                var hex = "";
                for (var j = 0; j < 256; j++) {
                    hex += ("0" + view[j].toString(16)).slice(-2);
                    if ((j + 1) % 16 === 0) {
                        console.log("[CODE] " + hex);
                        hex = "";
                    }
                }

                // Look for interesting patterns
                console.log("[SCAN] Looking for patterns...");

                // MOVABS rax (0x48 0xb8)
                for (var j = 0; j < 1020; j++) {
                    if (view[j] === 0x48 && view[j+1] === 0xb8) {
                        var lo = 0, hi = 0;
                        for (var k = 0; k < 4; k++) {
                            lo += (view[j+2+k] << (k*8));
                            hi += (view[j+6+k] << (k*8));
                        }
                        var imm = lo + hi * 0x100000000;
                        console.log("[MOVABS +" + j + "] rax=0x" + ("0000000000000000" + imm.toString(16)).slice(-16));
                    }
                }

                // Look for LEA rip-relative (0x48 0x8d 0x05)
                for (var j = 0; j < 1020; j++) {
                    if (view[j] === 0x48 && view[j+1] === 0x8d && view[j+2] === 0x05) {
                        var disp = view[j+3] | (view[j+4] << 8) | (view[j+5] << 16) | (view[j+6] << 24);
                        if (disp > 0x80000000) disp -= 0x100000000;
                        var target = fn.add(j + 7 + disp);
                        console.log("[LEA +" + j + "] -> " + target);

                        // Read data at target
                        try {
                            var tdata = target.readByteArray(64);
                            var tv = new Uint8Array(tdata);
                            var thex = "";
                            for (var k = 0; k < 64; k++) thex += ("0" + tv[k].toString(16)).slice(-2);
                            console.log("[LEA_DATA] " + thex);

                            // Check if it's a string
                            var str = "";
                            for (var k = 0; k < 64; k++) {
                                if (tv[k] >= 32 && tv[k] < 127) {
                                    str += String.fromCharCode(tv[k]);
                                } else if (tv[k] === 0) {
                                    break;
                                } else {
                                    str = "";
                                    break;
                                }
                            }
                            if (str.length > 3) {
                                console.log("[LEA_STR] \"" + str + "\"");
                            }
                        } catch(e) {}
                    }
                }

                // Look for CALL instructions
                for (var j = 0; j < 1020; j++) {
                    if (view[j] === 0xe8) {
                        var disp = view[j+1] | (view[j+2] << 8) | (view[j+3] << 16) | (view[j+4] << 24);
                        if (disp > 0x80000000) disp -= 0x100000000;
                        var target = fn.add(j + 5 + disp);
                        console.log("[CALL +" + j + "] -> " + target);
                    }
                }
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
