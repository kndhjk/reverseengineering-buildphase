"use strict";
console.log("[INIT] Loading...");

Java.perform(function() {
    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}
    try { Java.use("X5").i.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("G4").e.implementation = function() { return true; }; } catch(e) {}
    try { Java.use("F0").f.implementation = function() { return true; }; } catch(e) {}

    // Hook URL.openConnection
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            if (url.indexOf("elliottwen") !== -1 || url.indexOf("auth") !== -1 || url.indexOf("generate") !== -1) {
                console.log("[URL] " + url);
            }
            return this.openConnection();
        };
        console.log("[HOOK] URL");
    } catch(e) {}

    // Hook HttpsURLConnection
    try {
        var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsConn.setRequestProperty.implementation = function(key, value) {
            console.log("[HTTPS] " + key + " = " + (value ? value.substring(0, 200) : "null"));
            return this.setRequestProperty(key, value);
        };
        console.log("[HOOK] HttpsConn");
    } catch(e) {}

    // Hook URLConnection
    try {
        var URLConn = Java.use("java.net.URLConnection");
        URLConn.setRequestProperty.implementation = function(key, value) {
            console.log("[CONN] " + key + " = " + (value ? value.substring(0, 200) : "null"));
            return this.setRequestProperty(key, value);
        };
        console.log("[HOOK] URLConn");
    } catch(e) {}

    // Hook _z05
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z05.implementation = function(a, b, c) {
            var result = this._z05(a, b, c);
            console.log("[_z05] " + result);
            return result;
        };
    } catch(e) {}

    // Hook _z06
    try {
        var NAB = Java.use("nz.ac.auckland.se702.reverseai.security.NativeAuthBridge");
        NAB._z06.implementation = function(a) {
            console.log("[_z06] called");
            return this._z06(a);
        };
    } catch(e) {}

    // Hook class v methods
    try {
        var v_cls = Java.use("v");
        v_cls.d.overload("r5", "java.util.Set", "boolean").implementation = function(a, b, c) {
            var r = this.d(a, b, c);
            console.log("[v.d] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
        v_cls.e.overload("M5").implementation = function(a) {
            var r = this.e(a);
            console.log("[v.e] " + (r ? r.substring(0, 300) : "null"));
            return r;
        };
    } catch(e) {}

    // Hook SharedPreferences
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP] " + key + " = " + (val ? val.substring(0, 100) : "null"));
            return val;
        };
    } catch(e) {}

    // Hook Base64 encodeToString to catch key encoding
    try {
        var B64 = Java.use("android.util.Base64");
        B64.encodeToString.overload("[B", "int").implementation = function(input, flags) {
            var r = this.encodeToString(input, flags);
            if (input.length >= 16) {
                console.log("[B64] encode len=" + input.length + " -> " + r.substring(0, 80));
            }
            return r;
        };
    } catch(e) {}

    // Hook X5 methods
    try {
        var X5 = Java.use("X5");
        X5.a.overload("[B").implementation = function(input) {
            var result = this.a(input);
            console.log("[X5.a] decrypt");
            return result;
        };
        X5.f.implementation = function() {
            var r = this.f();
            console.log("[X5.f] key blob");
            return r;
        };
    } catch(e) {}

    console.log("[INIT] Done. Tap Generate...");
});
