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

    // Enumerate ALL loaded classes and find ones with addHeader/header methods
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.length > 5) return;
            try {
                var cls = Java.use(className);
                var methods = cls.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var name = m.getName();
                    if (name === "addHeader" || name === "header") {
                        var params = m.getParameterTypes();
                        if (params.length === 2 && 
                            params[0].getName() === "java.lang.String" && 
                            params[1].getName() === "java.lang.String") {
                            console.log("[FOUND] " + className + "." + name + "(String,String)");
                            (function(cn, mn) {
                                cls[mn].overload("java.lang.String", "java.lang.String").implementation = function(k, v) {
                                    console.log("[" + cn + "." + mn + "] " + k + " = " + (v ? v.substring(0, 200) : "null"));
                                    return this[mn](k, v);
                                };
                            })(className, name);
                        }
                    }
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });

    // Also hook A7.b (request builder from earlier analysis)
    try {
        var A7 = Java.use("A7");
        A7.b.overload("java.lang.String", "java.lang.String").implementation = function(k, v) {
            console.log("[A7.b] " + k + " = " + (v ? v.substring(0, 200) : "null"));
            return this.b(k, v);
        };
        console.log("[HOOK] A7.b");
    } catch(e) {}

    console.log("[INIT] Done");
});
