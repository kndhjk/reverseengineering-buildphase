"use strict";
var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var rnPtr = vtable.add(215 * Process.pointerSize).readPointer();
var inZ05 = false;

// Hook clock_gettime, gettimeofday, time
var clock_gettime = Module.findExportByName("libc.so", "clock_gettime");
if (clock_gettime) {
    Interceptor.attach(clock_gettime, {
        onEnter: function(args) {
            if (inZ05) console.log("[CLOCK] clock_gettime called");
        }
    });
}

var gettimeofday = Module.findExportByName("libc.so", "gettimeofday");
if (gettimeofday) {
    Interceptor.attach(gettimeofday, {
        onEnter: function(args) {
            if (inZ05) console.log("[TIME] gettimeofday called");
        }
    });
}

// Hook arc4random / getrandom
var getrandom = Module.findExportByName("libc.so", "getrandom");
if (getrandom) {
    Interceptor.attach(getrandom, {
        onEnter: function(args) {
            if (inZ05) console.log("[RAND] getrandom called, len=" + args[1].toInt32());
        }
    });
}

var arc4random = Module.findExportByName("libc.so", "arc4random");
if (arc4random) {
    Interceptor.attach(arc4random, {
        onEnter: function() {
            if (inZ05) console.log("[RAND] arc4random called");
        }
    });
}

Interceptor.attach(rnPtr, {
    onEnter: function(args) {
        var m = args[2];
        var n = args[3].toInt32();
        for (var i = 0; i < n; i++) {
            var entry = m.add(i * Process.pointerSize * 3);
            var name = entry.readPointer().readUtf8String();
            var fn = entry.add(Process.pointerSize * 2).readPointer();

            if (name === "_z05") {
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        inZ05 = true;
                        console.log("[_z05] ENTER");
                    },
                    onLeave: function(retval) {
                        inZ05 = false;
                        console.log("[_z05] LEAVE");
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
            var db = Java.array("byte", [0xd2,0xc7,0xb3,0xa3,0xfc,0x4d,0x24,0x7d,0x01,0xe1,0x88,0xcb,0xf4,0x04,0xd4,0x7c,0xc5,0x7a,0xf2,0x10,0xe9,0xf4,0xab,0x79,0x07,0xc9,0x5f,0xa3,0x61,0xde,0x5b,0x70]);
            var hb = Java.array("byte", [0xad,0x48,0xad,0x35,0xdf,0x97,0x9c,0x23,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
            var result = this._z05(a, db, hb);
            console.log("[_z05_java] " + result);
            return result;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
