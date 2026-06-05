"use strict";
console.log("[INIT] Loading...");

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook ALL classes that might handle HTTP
    // Class v is the API client - hook ALL its methods
    try {
        var v_cls = Java.use("v");
        var methods = v_cls.class.getDeclaredMethods();
        console.log("[v] Methods: " + methods.length);
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            var params = m.getParameterTypes();
            var pnames = [];
            for (var j = 0; j < params.length; j++) pnames.push(params[j].getName());
            console.log("[v] " + name + "(" + pnames.join(",") + ") -> " + ret);
        }
    } catch(e) { console.log("[ERR] v: " + e); }

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

    // Hook ALL String-returning methods in ALL single-letter classes
    var singleClasses = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",
                         "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"];
    singleClasses.forEach(function(cn) {
        try {
            var cls = Java.use(cn);
            var meths = cls.class.getDeclaredMethods();
            for (var i = 0; i < meths.length; i++) {
                var m = meths[i];
                var ret = m.getReturnType().getName();
                var name = m.getName();
                var params = m.getParameterTypes();
                if (ret === "java.lang.String" && params.length <= 2) {
                    (function(cn2, mn, pc) {
                        try {
                            if (pc === 0) {
                                cls[mn].overload().implementation = function() {
                                    var r = this[mn]();
                                    if (r && r.length > 10) {
                                        console.log("[" + cn2 + "." + mn + "()] " + r.substring(0, 200));
                                    }
                                    return r;
                                };
                            }
                        } catch(e3) {}
                    })(cn, name, params.length);
                }
            }
        } catch(e2) {}
    });

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val.substring(0, 100) : "null"));
            return val;
        };
    } catch(e) {}

    // Hook Base64
    try {
        var B64 = Java.use("android.util.Base64");
        B64.encodeToString.overload("[B", "int").implementation = function(input, flags) {
            var r = this.encodeToString(input, flags);
            if (input.length >= 32) {
                console.log("[B64enc] len=" + input.length + " -> " + r.substring(0, 80));
            }
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
});
