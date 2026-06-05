"use strict";

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var rnPtr = vtable.add(215 * Process.pointerSize).readPointer();
var inZ05 = false;
var frozenTime = {tv_sec: 1780600000, tv_nsec: 0};

// Hook clock_gettime to return frozen time when in _z05
var clock_gettime = Module.findExportByName("libc.so", "clock_gettime");
if (clock_gettime) {
    Interceptor.attach(clock_gettime, {
        onEnter: function(args) {
            if (inZ05) {
                this.tp = args[1];
            }
        },
        onLeave: function(retval) {
            if (inZ05 && this.tp) {
                // Write frozen time
                this.tp.writeS64(frozenTime.tv_sec);
                this.tp.add(8).writeS64(frozenTime.tv_nsec);
            }
        }
    });
    console.log("[HOOK] clock_gettime");
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
                        console.log("[_z05] ENTER (time frozen)");
                    },
                    onLeave: function(retval) {
                        inZ05 = false;
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

    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var db = Java.array("byte", [0xd2,0xc7,0xb3,0xa3,0xfc,0x4d,0x24,0x7d,0x01,0xe1,0x88,0xcb,0xf4,0x04,0xd4,0x7c,0xc5,0x7a,0xf2,0x10,0xe9,0xf4,0xab,0x79,0x07,0xc9,0x5f,0xa3,0x61,0xde,0x5b,0x70]);
            var hb = Java.array("byte", [0xad,0x48,0xad,0x35,0xdf,0x97,0x9c,0x23,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
            var result = this._z05(a, db, hb);
            console.log("[_z05] RESULT: " + result);
            return result;
        };
    } catch(e) {}

    // Call _z05 multiple times to see if frozen time produces same key
    setTimeout(function() {
        try {
            var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
            for (var i = 0; i < 3; i++) {
                var db = Java.array("byte", [0xd2,0xc7,0xb3,0xa3,0xfc,0x4d,0x24,0x7d,0x01,0xe1,0x88,0xcb,0xf4,0x04,0xd4,0x7c,0xc5,0x7a,0xf2,0x10,0xe9,0xf4,0xab,0x79,0x07,0xc9,0x5f,0xa3,0x61,0xde,0x5b,0x70]);
                var hb = Java.array("byte", [0xad,0x48,0xad,0x35,0xdf,0x97,0x9c,0x23,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
                var empty = Java.array("byte", []);
                var result = NAB._z05(empty, db, hb);
                console.log("[TEST" + i + "] " + result);
            }
        } catch(e) { console.log("[ERR] " + e); }
    }, 5000);

    console.log("[INIT] Done");
});
