#!/usr/bin/env python3
"""Dump ALL SharedPreferences values from vitality."""
import frida
import time
import subprocess

ADB = r"C:\Users\zyzmc\AppData\Local\Android\Sdk\platform-tools\adb.exe"
device = frida.get_device('emulator-5554', timeout=5)
session = device.attach('Vitality AI')

JS = r'''
"use strict";

Java.perform(function() {
    console.log("[INIT] Dumping SharedPreferences...");

    // Get the app context
    var ActivityThread = Java.use("android.app.ActivityThread");
    var app = ActivityThread.currentApplication();
    var ctx = app.getApplicationContext();

    // Get SharedPreferences
    var sp = ctx.getSharedPreferences("v_p1", 0);
    var all = sp.getAll();
    var keys = all.keySet().iterator();

    console.log("[SP] === SharedPreferences 'v_p1' ===");
    while (keys.hasNext()) {
        var key = keys.next();
        var val = all.get(key);
        var valStr = val ? val.toString() : "null";
        console.log("[SP] " + key + " = " + valStr.substring(0, 500));
    }
    console.log("[SP] === End ===");

    // Also check other preference files
    try {
        var files = ctx.fileList();
        console.log("[FILES] App files:");
        for (var i = 0; i < files.length; i++) {
            console.log("[FILES] " + files[i]);
        }
    } catch(e) {}

    // Try to read SharedPreferences XML directly
    try {
        var File = Java.use("java.io.File");
        var prefsDir = ctx.getFilesDir().getParent() + "/shared_prefs/";
        console.log("[SP_DIR] " + prefsDir);
        var dir = File.$new(prefsDir);
        var files = dir.listFiles();
        if (files) {
            for (var i = 0; i < files.length; i++) {
                console.log("[SP_FILE] " + files[i].getName());
            }
        }
    } catch(e) { console.log("[ERR] SP dir: " + e); }

    // Hook SharedPreferencesImpl to capture all reads
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            console.log("[SP_READ] getString(" + key + ") = " + (val ? val.substring(0, 300) : "null"));
            return val;
        };
        console.log("[HOOK] SP.getString");
    } catch(e) { console.log("[ERR] SP hook: " + e); }

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

    console.log("[INIT] Done.");
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
