#!/usr/bin/env python3
"""Find the actual HTTP client class used by vitality."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')

JS = r'''
"use strict";

Java.perform(function() {
    console.log("[INIT] Enumerating classes...");

    // Find all classes and look for HTTP-related ones
    var httpClasses = [];
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Look for OkHttp-like classes (single letter or short names)
            if (className.length <= 3 && !className.startsWith("L") && !className.startsWith("[")) {
                httpClasses.push(className);
            }
            // Also look for classes with http/url/request in name
            if (className.toLowerCase().indexOf("http") !== -1 ||
                className.toLowerCase().indexOf("url") !== -1 ||
                className.toLowerCase().indexOf("request") !== -1 ||
                className.toLowerCase().indexOf("call") !== -1 ||
                className.toLowerCase().indexOf("client") !== -1) {
                console.log("[HTTP_CLASS] " + className);
            }
        },
        onComplete: function() {
            console.log("[INFO] Short-named classes: " + httpClasses.join(", "));
        }
    });

    // Try to hook methods in class 'v' that might do HTTP
    try {
        var v_cls = Java.use("v");
        var methods = v_cls.class.getDeclaredMethods();
        console.log("[CLASS_V] Methods:");
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var name = m.getName();
            var ret = m.getReturnType().getName();
            var params = m.getParameterTypes();
            var paramStr = [];
            for (var j = 0; j < params.length; j++) paramStr.push(params[j].getName());
            console.log("[CLASS_V] " + name + "(" + paramStr.join(", ") + ") -> " + ret);
        }
    } catch(e) { console.log("[ERR] class v: " + e); }

    // Try to find classes that implement Call.Factory or similar
    try {
        var classes = ["v", "u", "s6", "F0", "G4", "X5", "N9"];
        for (var ci = 0; ci < classes.length; ci++) {
            try {
                var cls = Java.use(classes[ci]);
                var interfaces = cls.class.getInterfaces();
                var superClass = cls.class.getSuperclass();
                var ifaceStr = [];
                for (var ii = 0; ii < interfaces.length; ii++) ifaceStr.push(interfaces[ii].getName());
                console.log("[CLASS] " + classes[ci] + " extends " + (superClass ? superClass.getName() : "null") + " implements " + ifaceStr.join(", "));
            } catch(e2) {}
        }
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

    // Bypass
    try {
        Java.use("X5").i.implementation = function() { return true; };
        Java.use("G4").e.implementation = function() { return true; };
        Java.use("F0").f.implementation = function() { return true; };
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}

    console.log("[INIT] Ready. Tap Generate...");
});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        print(msg.get('payload', ''))
    elif msg.get('type') == 'error':
        desc = msg.get('description', '')
        if 'send' not in desc.lower() and 'cast' not in desc.lower() and 'properties' not in desc.lower():
            print(f'[ERR] {desc[:200]}')

script = session.create_script(JS, runtime='v8')
script.on('message', on_message)
script.load()
time.sleep(5)

session.detach()
print('[*] Done')
