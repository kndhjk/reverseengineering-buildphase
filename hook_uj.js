"use strict";
Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

    // Hook u.j - this calls _z05
    try {
        var u_cls = Java.use("u");
        // u.j takes some args and returns something
        var methods = u_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            var params = m.getParameterTypes();
            var pnames = [];
            for (var j = 0; j < params.length; j++) pnames.push(params[j].getName());
            console.log("[u] " + name + "(" + pnames.join(",") + ") -> " + ret);
        }

        // Hook u.j specifically
        u_cls.j.implementation = function() {
            console.log("[u.j] called with " + arguments.length + " args");
            for (var a = 0; a < arguments.length; a++) {
                var arg = arguments[a];
                if (arg && typeof arg === 'object' && arg.getClass) {
                    console.log("[u.j] arg" + a + " type=" + arg.getClass().getName());
                } else {
                    console.log("[u.j] arg" + a + " = " + arg);
                }
            }
            var result = this.j.apply(this, arguments);
            console.log("[u.j] returned: " + (result ? result.toString().substring(0, 200) : "null"));
            return result;
        };
        console.log("[HOOK] u.j");
    } catch(e) { console.log("[ERR] u.j: " + e); }

    // Hook u.h
    try {
        var u_cls = Java.use("u");
        u_cls.h.implementation = function() {
            console.log("[u.h] called");
            var result = this.h.apply(this, arguments);
            console.log("[u.h] returned: " + (result ? result.toString().substring(0, 200) : "null"));
            return result;
        };
        console.log("[HOOK] u.h");
    } catch(e) { console.log("[ERR] u.h: " + e); }

    // Hook t2 methods
    try {
        var t2_cls = Java.use("t2");
        var methods = t2_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            (function(mn) {
                try {
                    t2_cls[mn].implementation = function() {
                        console.log("[t2." + mn + "] called");
                        return this[mn].apply(this, arguments);
                    };
                } catch(e2) {}
            })(name);
        }
        console.log("[HOOK] t2");
    } catch(e) { console.log("[ERR] t2: " + e); }

    // Hook Z.b
    try {
        var Z_cls = Java.use("Z");
        Z_cls.b.implementation = function() {
            console.log("[Z.b] called");
            var result = this.b.apply(this, arguments);
            console.log("[Z.b] returned: " + (result ? result.toString().substring(0, 200) : "null"));
            return result;
        };
        console.log("[HOOK] Z.b");
    } catch(e) { console.log("[ERR] Z.b: " + e); }

    // Hook v.a to see the final key
    try {
        var v_cls = Java.use("v");
        v_cls.a.overload("v", "H1", "java.lang.String").implementation = function(self, h1, s) {
            console.log("[v.a] FINAL KEY: " + (s ? s : "null"));
            return this.a(self, h1, s);
        };
        console.log("[HOOK] v.a");
    } catch(e) {}

    // Hook v.c to see response
    try {
        var v_cls = Java.use("v");
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(p7, s, h1) {
            console.log("[v.c] " + (s ? s.substring(0, 200) : "null"));
            return this.c(p7, s, h1);
        };
    } catch(e) {}

    // Hook v.e
    try {
        var v_cls = Java.use("v");
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
