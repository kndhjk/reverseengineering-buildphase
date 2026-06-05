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

    // Hook ALL methods in class v
    try {
        var v_cls = Java.use("v");
        v_cls.a.overload("v", "H1", "java.lang.String").implementation = function(self, h1, s) {
            console.log("[v.a] s=" + (s ? s.substring(0, 200) : "null"));
            return this.a(self, h1, s);
        };
        v_cls.b.overload("v", "java.lang.String", "java.lang.String", "java.lang.String", "H1").implementation = function(self, url, method, body, h1) {
            console.log("[v.b] url=" + url + " method=" + method + " body=" + (body ? body.substring(0, 200) : "null"));
            return this.b(self, url, method, body, h1);
        };
        v_cls.c.overload("p7", "java.lang.String", "H1").implementation = function(p7, s, h1) {
            console.log("[v.c] s=" + (s ? s.substring(0, 200) : "null"));
            return this.c(p7, s, h1);
        };
    } catch(e) { console.log("[ERR] v: " + e); }

    // Hook ALL methods in class A7 (request builder)
    try {
        var A7 = Java.use("A7");
        A7.b.overload("java.lang.String", "java.lang.String").implementation = function(k, v) {
            console.log("[A7.b] " + k + " = " + (v ? v.substring(0, 200) : "null"));
            return this.b(k, v);
        };
        A7.c.overload("java.lang.String", "C7").implementation = function(method, body) {
            console.log("[A7.c] method=" + method);
            return this.c(method, body);
        };
        A7.d.overload("java.lang.String").implementation = function(url) {
            console.log("[A7.d] " + url);
            return this.d(url);
        };
    } catch(e) {}

    // Hook class B7 (request)
    try {
        var B7 = Java.use("B7");
        B7.toString.implementation = function() {
            var r = this.toString();
            console.log("[B7] " + r.substring(0, 500));
            return r;
        };
    } catch(e) {}

    // Hook class v.e to see response
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
