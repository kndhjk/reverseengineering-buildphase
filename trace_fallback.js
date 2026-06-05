"use strict";
// Trace the FULL auth flow to find where the real key comes from
// _z05 returns decoy -> app gets "Authentication failed" -> what happens next?

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

    // Hook ALL methods in class v (API client)
    try {
        var v_cls = Java.use("v");
        var methods = v_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            var params = m.getParameterTypes();
            var pnames = [];
            for (var j = 0; j < params.length; j++) pnames.push(params[j].getName());
            // Hook all methods
            (function(cn, mn, rt, pc) {
                try {
                    if (rt === "java.lang.String" && pc === 0) {
                        v_cls[mn].overload().implementation = function() {
                            var r = this[mn]();
                            console.log("[" + cn + "." + mn + "()] " + (r ? r.substring(0, 200) : "null"));
                            return r;
                        };
                    }
                } catch(e2) {}
            })(v_cls, name, ret, params.length);
        }
    } catch(e) { console.log("[ERR] v: " + e); }

    // Hook ALL methods in class u
    try {
        var u_cls = Java.use("u");
        var methods = u_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            (function(mn) {
                try {
                    u_cls[mn].implementation = function() {
                        console.log("[u." + mn + "] called");
                        return this[mn].apply(this, arguments);
                    };
                } catch(e2) {}
            })(name);
        }
    } catch(e) { console.log("[ERR] u: " + e); }

    // Hook ALL methods in class Z
    try {
        var Z_cls = Java.use("Z");
        var methods = Z_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            (function(mn) {
                try {
                    Z_cls[mn].implementation = function() {
                        console.log("[Z." + mn + "] called");
                        return this[mn].apply(this, arguments);
                    };
                } catch(e2) {}
            })(name);
        }
    } catch(e) { console.log("[ERR] Z: " + e); }

    // Hook class t2 (from call chain)
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
    } catch(e) { console.log("[ERR] t2: " + e); }

    // Hook class p (from second call chain)
    try {
        var p_cls = Java.use("p");
        var methods = p_cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            (function(mn) {
                try {
                    p_cls[mn].implementation = function() {
                        console.log("[p." + mn + "] called");
                        return this[mn].apply(this, arguments);
                    };
                } catch(e2) {}
            })(name);
        }
    } catch(e) { console.log("[ERR] p: " + e); }

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val.substring(0, 100) : "null"));
            return val;
        };
    } catch(e) {}

    // Hook SecretKeySpec
    try {
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function(bytes, algo) {
            var hex = "";
            for (var i = 0; i < Math.min(bytes.length, 64); i++) hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
            console.log("[SKS] algo=" + algo + " len=" + bytes.length + " hex=" + hex);
            return this.$init(bytes, algo);
        };
    } catch(e) {}

    // Hook Cipher
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                var kb = key.getEncoded();
                if (kb) {
                    var hex = "";
                    for (var i = 0; i < Math.min(kb.length, 64); i++) hex += ("0" + (kb[i] & 0xFF).toString(16)).slice(-2);
                    console.log("[CIPHER] mode=" + (mode===1?"ENC":"DEC") + " algo=" + this.getAlgorithm() + " key=" + hex);
                }
            } catch(e2) {}
            return this.init(mode, key, params);
        };
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
});
