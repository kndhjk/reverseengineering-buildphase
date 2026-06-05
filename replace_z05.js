"use strict";
console.log("[INIT] Loading...");

var env = Java.vm.getEnv();
var vtable = env.handle.readPointer();
var registerNativesPtr = vtable.add(215 * Process.pointerSize).readPointer();
var newStringUTF = vtable.add(169 * Process.pointerSize).readPointer();

Interceptor.attach(registerNativesPtr, {
    onEnter: function(args) {
        var methods = args[2];
        var numMethods = args[3].toInt32();
        for (var i = 0; i < numMethods; i++) {
            var entry = methods.add(i * Process.pointerSize * 3);
            var namePtr = entry.readPointer();
            var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
            var name = namePtr.readUtf8String();

            if (name === "_z05") {
                console.log("[FOUND] _z05 at " + fnPtr);
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("[_z05] CALLED");
                    },
                    onLeave: function(retval) {
                        console.log("[_z05] Original retval=" + retval);
                        // Replace with shared key
                        var jniEnv = env.handle;
                        var testKey = "7a4212da71a964f875981dcfcc9d0b2e3b6db72fe5e614191b6f521dcb9fdebeaf1706c36f6f308da72a7ba762aafd3398e9113e93df0e437dfc3a153172dad7";
                        var newStrFn = new NativeFunction(newStringUTF, 'pointer', ['pointer', 'pointer']);
                        var newJstring = newStrFn(jniEnv, Memory.allocUtf8String(testKey));
                        console.log("[_z05] Replaced with shared key");
                        retval.replace(newJstring);
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
});
console.log("[INIT] Done");
