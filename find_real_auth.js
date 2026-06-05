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

    // Hook v.a to see the key and where it comes from
    try {
        var v_cls = Java.use("v");
        v_cls.a.overload("v", "H1", "java.lang.String").implementation = function(self, h1, s) {
            console.log("[v.a] key=" + (s ? s.substring(0, 200) : "null"));
            // Print stack trace to see who called this
            console.log("[v.a] caller: " + Java.use("java.lang.Thread").currentThread().getStackTrace());
            return this.a(self, h1, s);
        };
    } catch(e) { console.log("[ERR] v.a: " + e); }

    // Hook v.b to see the full request
    try {
        var v_cls = Java.use("v");
        v_cls.b.overload("v", "java.lang.String", "java.lang.String", "java.lang.String", "H1").implementation = function(self, url, method, body, h1) {
            console.log("[v.b] url=" + url + " method=" + method);
            console.log("[v.b] body=" + (body ? body.substring(0, 200) : "null"));
            return this.b(self, url, method, body, h1);
        };
    } catch(e) {}

    // Hook v.c to see response
    try {
        var v_cls = Java.use("v");
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(p7, s, h1) {
            console.log("[v.c] " + (s ? s.substring(0, 200) : "null"));
            return this.c(p7, s, h1);
        };
    } catch(e) {}

    // Hook A7 to see all request building
    try {
        var A7 = Java.use("A7");
        A7.a.overload().implementation = function() {
            var r = this.a();
            console.log("[A7.a] " + (r ? r.toString().substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    // Hook B7 (request) toString
    try {
        var B7 = Java.use("B7");
        B7.toString.implementation = function() {
            var r = this.toString();
            console.log("[B7.toString] " + r.substring(0, 500));
            return r;
        };
    } catch(e) {}

    // Hook p7.a to see request details
    try {
        var p7 = Java.use("p7");
        p7.a.overload("p7").implementation = function(a) {
            var r = this.a(a);
            console.log("[p7.a] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done");
});
