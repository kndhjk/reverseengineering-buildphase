'use strict';
/**
 * Frida hook for Tartarus APK (nz.ac.auckland.cs702.tartarus)
 *
 * Goal: Extract the real API key from native code (libtartarus_core.so)
 * and capture the Authorization header used in HTTP requests.
 *
 * Hooks:
 *  1. Anti-tamper bypass (RuntimeProbe, root detection, debugger checks)
 *  2. Native JNI method interception (probeEndpoint, probeGate, warmupNative, etc.)
 *  3. curl_easy_setopt in libtartarus_core.so for raw HTTP capture
 *  4. JNI NewStringUTF to capture ALL strings returned from native code
 *  5. OkHttp RequestBuilder for Java-layer HTTP interception
 *  6. SharedPreferences monitoring
 *  7. Anti-Frida bypass (hide from /proc/self/maps scanning)
 */

var captured = {
    keys: [],
    urls: [],
    headers: [],
    nativeStrings: []
};

function hexEncode(bytes, maxLen) {
    maxLen = maxLen || bytes.length;
    var hex = '';
    for (var i = 0; i < Math.min(bytes.length, maxLen); i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

function log(tag, msg) {
    var line = '[' + tag + '] ' + msg;
    console.log(line);
    send({type: 'capture', tag: tag, data: msg});
}

// =====================================================
// PHASE 1: Anti-Tamper Bypass (runs immediately)
// =====================================================

// Bypass RuntimeProbe.inspectRuntime() - must return false to pass checks
try {
    var RuntimeProbe = Java.use('com.example.playground.util.RuntimeProbe');
    RuntimeProbe.inspectRuntime.implementation = function () {
        log('BYPASS', 'inspectRuntime() -> false');
        return false;
    };
    log('HOOK', 'RuntimeProbe.inspectRuntime bypassed');
} catch (e) {
    log('ERR', 'RuntimeProbe: ' + e);
}

// Bypass Debug.isDebuggerConnected / waitForDebugger
try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () { return false; };
    Debug.waitForDebugger.implementation = function () { };
    log('HOOK', 'Debug checks bypassed');
} catch (e) {}

// Bypass root detection: File.exists() for su/magisk paths
try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1 ||
            path.indexOf('busybox') !== -1 || path.indexOf('Superuser') !== -1) {
            log('BYPASS', 'File.exists(' + path + ') -> false');
            return false;
        }
        return this.exists();
    };
    log('HOOK', 'Root file detection bypassed');
} catch (e) {}

// Bypass Build.TAGS check for "test-keys"
try {
    var Build = Java.use('android.os.Build');
    var TAGS_FIELD = Build.TAGS;
    // We can't easily override a static final field, but we can hook methods that read it
    log('INFO', 'Build.TAGS = ' + TAGS_FIELD.value);
} catch (e) {}

// =====================================================
// PHASE 2: Anti-Frida Bypass
// =====================================================

// Hook libc open() to block /proc/self/maps reads that scan for "frida"
var libc = Module.findExportByName('libc.so', 'open');
if (libc) {
    Interceptor.attach(libc, {
        onEnter: function (args) {
            try {
                var path = args[0].readUtf8String();
                if (path && (path.indexOf('/proc/self/maps') !== -1 ||
                             path.indexOf('/proc/self/status') !== -1 ||
                             path.indexOf('/proc/self/cmdline') !== -1)) {
                    this.blocked = true;
                    log('ANTI-FRIDA', 'Blocked open(' + path + ')');
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.blocked) {
                retval.replace(-1);
            }
        }
    });
    log('HOOK', 'libc.open() anti-frida bypass active');
}

// Hook strstr() to hide "frida" strings
var strstr = Module.findExportByName('libc.so', 'strstr');
if (strstr) {
    Interceptor.attach(strstr, {
        onEnter: function (args) {
            try {
                var needle = args[1].readUtf8String();
                if (needle && needle.indexOf('frida') !== -1) {
                    this.hide = true;
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.hide) {
                retval.replace(ptr(0));
            }
        }
    });
    log('HOOK', 'strstr() frida-hiding active');
}

// =====================================================
// PHASE 3: Core JNI Native Method Hooks
// =====================================================

Java.perform(function () {
    log('INIT', 'Java.perform started');

    // --- AssetProbe: probeEndpoint() and probeGate() ---
    try {
        var AssetProbe = Java.use('com.example.playground.utils.AssetProbe');

        // First, CALL the methods to get the values
        var probe = AssetProbe.$new();
        try {
            var endpoint = probe.probeEndpoint();
            log('KEY_FOUND', 'probeEndpoint() = "' + endpoint + '"');
            captured.keys.push({method: 'probeEndpoint', value: endpoint});
        } catch (e) {
            log('ERR', 'probeEndpoint call: ' + e);
        }

        try {
            var gate = probe.probeGate();
            log('KEY_FOUND', 'probeGate() = "' + gate + '"');
            captured.keys.push({method: 'probeGate', value: gate});
        } catch (e) {
            log('ERR', 'probeGate call: ' + e);
        }

        // Then HOOK them for future calls
        AssetProbe.probeEndpoint.implementation = function () {
            var val = this.probeEndpoint();
            log('HOOK_CALL', 'probeEndpoint() -> "' + val + '"');
            captured.keys.push({method: 'probeEndpoint', value: val, hook: true});
            return val;
        };

        AssetProbe.probeGate.implementation = function () {
            var val = this.probeGate();
            log('HOOK_CALL', 'probeGate() -> "' + val + '"');
            captured.keys.push({method: 'probeGate', value: val, hook: true});
            return val;
        };

        // Also try loadPalette which builds the auth request
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            var ctx = app ? app.getApplicationContext() : null;
            if (ctx) {
                var cacheDir = ctx.getCacheDir();
                var palette = probe.loadPalette(cacheDir);
                log('KEY_FOUND', 'loadPalette() = "' + palette + '"');
                captured.keys.push({method: 'loadPalette', value: palette});
            }
        } catch (e) {
            log('ERR', 'loadPalette: ' + e);
        }

        log('HOOK', 'AssetProbe hooks installed');
    } catch (e) {
        log('ERR', 'AssetProbe: ' + e);
    }

    // --- ImagePipeline$Companion ---
    try {
        var IPC = Java.use('com.example.playground.network.ImagePipeline$Companion');

        var methods = ['a', 'b', 'c', 'd', 'i', 'j'];
        methods.forEach(function (m) {
            try {
                var result = IPC[m]();
                log('KEY_FOUND', 'ImagePipeline.' + m + '() = "' + result + '"');
                captured.keys.push({method: 'ImagePipeline.' + m, value: result});
            } catch (e) {}
        });

        // Hook routeBase
        try {
            IPC.e.overload('java.lang.String').implementation = function (url) {
                var out = this.e(url);
                log('HOOK_CALL', 'routeBase("' + url + '") -> "' + out + '"');
                captured.urls.push({method: 'routeBase', in: url, out: out});
                return out;
            };
            log('HOOK', 'routeBase hooked');
        } catch (e) {}

        // Hook checkPeer
        try {
            IPC.checkPeer.implementation = function (cert, host) {
                var r = this.checkPeer(cert, host);
                log('HOOK_CALL', 'checkPeer(cert=' + cert.substring(0, 40) + '..., host=' + host + ') -> ' + r);
                return r;
            };
            log('HOOK', 'checkPeer hooked');
        } catch (e) {}

        log('HOOK', 'ImagePipeline hooks installed');
    } catch (e) {
        log('ERR', 'ImagePipeline: ' + e);
    }

    // --- PaletteProbe ---
    try {
        var PaletteProbe = Java.use('com.example.playground.network.PaletteProbe');
        var pp = PaletteProbe.$new();
        try {
            var palette = pp.readPalette();
            log('KEY_FOUND', 'readPalette() = "' + palette + '"');
            captured.keys.push({method: 'readPalette', value: palette});
        } catch (e) {}

        PaletteProbe.readPalette.implementation = function () {
            var val = this.readPalette();
            log('HOOK_CALL', 'readPalette() -> "' + val + '"');
            return val;
        };
        log('HOOK', 'PaletteProbe hooks installed');
    } catch (e) {
        log('ERR', 'PaletteProbe: ' + e);
    }

    // --- AssetWarmup ---
    try {
        var AssetWarmup = Java.use('com.example.playground.network.AssetWarmup');
        var ActivityThread2 = Java.use('android.app.ActivityThread');
        var app2 = ActivityThread2.currentApplication();
        var ctx2 = app2 ? app2.getApplicationContext() : null;
        if (ctx2) {
            try {
                var warmup = AssetWarmup.$new(ctx2);
                var warmupResult = warmup.warmupNative();
                log('KEY_FOUND', 'warmupNative() = "' + warmupResult + '"');
                captured.keys.push({method: 'warmupNative', value: warmupResult});
            } catch (e) {
                log('ERR', 'warmupNative call: ' + e);
            }
        }

        AssetWarmup.warmupNative.implementation = function () {
            var val = this.warmupNative();
            log('HOOK_CALL', 'warmupNative() -> "' + val + '"');
            return val;
        };
        log('HOOK', 'AssetWarmup hooks installed');
    } catch (e) {
        log('ERR', 'AssetWarmup: ' + e);
    }

    // --- FrameAssembler ---
    try {
        var FrameAssembler = Java.use('com.example.playground.network.FrameAssembler');
        FrameAssembler.composeFrame.overload('java.lang.String').implementation = function (prompt) {
            var val = this.composeFrame(prompt);
            log('HOOK_CALL', 'composeFrame("' + prompt + '") -> "' + val + '"');
            return val;
        };
        log('HOOK', 'FrameAssembler hooked');
    } catch (e) {
        log('ERR', 'FrameAssembler: ' + e);
    }

    // --- Token Factory G1.j ---
    try {
        var TokenFactory = Java.use('G1.j');
        TokenFactory.b.implementation = function () {
            var val = this.b();
            log('KEY_FOUND', 'G1.j.b() token = "' + val + '"');
            captured.keys.push({method: 'G1.j.b', value: val});
            return val;
        };
        log('HOOK', 'G1.j.b token factory hooked');
    } catch (e) {
        log('ERR', 'G1.j.b: ' + e);
    }

    // --- OkHttp RequestBuilder (A0.p) ---
    try {
        var RB = Java.use('A0.p');
        RB.p.overload('java.lang.String').implementation = function (url) {
            log('HTTP', 'Request URL: ' + url);
            captured.urls.push({source: 'RequestBuilder', url: url});
            return this.p(url);
        };
        RB.m.overload('java.lang.String', 'java.lang.String').implementation = function (name, value) {
            log('HTTP', 'Header: ' + name + ' = ' + value);
            if (name.toLowerCase() === 'authorization') {
                log('AUTH_HEADER', 'Authorization: ' + value);
                captured.headers.push({name: name, value: value});
            }
            return this.m(name, value);
        };
        RB.o.overload('java.lang.String', 'A.l').implementation = function (method, body) {
            log('HTTP', 'Method: ' + method);
            return this.o(method, body);
        };
        log('HOOK', 'OkHttp RequestBuilder hooked');
    } catch (e) {
        log('ERR', 'RequestBuilder: ' + e);
    }

    // --- JSONObject.getString for 'signature' ---
    try {
        var JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getString.overload('java.lang.String').implementation = function (name) {
            var val = this.getString(name);
            if (name === 'signature' || name === 'token' || name === 'key') {
                log('JSON', 'getString("' + name + '") = "' + val + '"');
            }
            return val;
        };
        log('HOOK', 'JSONObject.getString hooked');
    } catch (e) {
        log('ERR', 'JSONObject: ' + e);
    }

    // --- SharedPreferences ---
    try {
        var SP = Java.use('android.app.SharedPreferencesImpl');
        SP.getString.implementation = function (key, def) {
            var val = this.getString(key, def);
            if (val && val.length > 10) {
                log('SP', 'getString("' + key + '") = "' + val.substring(0, 200) + '"');
            }
            return val;
        };
        SP.putString.implementation = function (key, value) {
            if (value && value.length > 10) {
                log('SP', 'putString("' + key + '") = "' + value.substring(0, 200) + '"');
            }
            return this.putString(key, value);
        };
        log('HOOK', 'SharedPreferences hooked');
    } catch (e) {
        log('ERR', 'SharedPreferences: ' + e);
    }

    log('INIT', 'All Java hooks installed');
});

// =====================================================
// PHASE 4: Native curl hooks (libtartarus_core.so)
// =====================================================

function setupNativeHooks() {
    var lib = null;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name === 'libtartarus_core.so') {
            lib = mods[i];
            break;
        }
    }
    if (!lib) {
        log('NATIVE', 'libtartarus_core.so not loaded yet, retrying in 1s...');
        setTimeout(setupNativeHooks, 1000);
        return;
    }
    log('NATIVE', 'libtartarus_core.so at ' + lib.base);

    // Hook curl_easy_setopt
    var curl_setopt = Module.findExportByName('libtartarus_core.so', 'curl_easy_setopt');
    if (!curl_setopt) curl_setopt = Module.findExportByName(null, 'curl_easy_setopt');
    if (curl_setopt) {
        Interceptor.attach(curl_setopt, {
            onEnter: function (args) {
                var opt = args[1].toInt32();
                try {
                    if (opt === 10002) { // CURLOPT_URL
                        var url = args[2].readUtf8String();
                        log('CURL', 'URL: ' + url);
                        captured.urls.push({source: 'curl', url: url});
                    }
                    if (opt === 10015) { // CURLOPT_POSTFIELDS
                        var body = args[2].readUtf8String();
                        if (body && body.length > 2) {
                            log('CURL', 'BODY: ' + body.substring(0, 500));
                        }
                    }
                    if (opt === 10023) { // CURLOPT_HTTPHEADER
                        var slist = args[2];
                        if (!slist.isNull()) {
                            var node = slist;
                            for (var j = 0; j < 30; j++) {
                                try {
                                    var dp = node.readPointer();
                                    if (dp.isNull()) break;
                                    var hdr = dp.readUtf8String();
                                    log('CURL', 'HEADER: ' + hdr);
                                    if (hdr && hdr.toLowerCase().indexOf('authorization') !== -1) {
                                        log('AUTH_HEADER', 'CURL Auth: ' + hdr);
                                        captured.headers.push({source: 'curl', value: hdr});
                                    }
                                    node = node.add(Process.pointerSize);
                                } catch (e) { break; }
                            }
                        }
                    }
                } catch (e) {}
            }
        });
        log('HOOK', 'curl_easy_setopt hooked');
    } else {
        log('ERR', 'curl_easy_setopt not found');
    }

    // Hook curl_easy_perform
    var curl_perform = Module.findExportByName('libtartarus_core.so', 'curl_easy_perform');
    if (!curl_perform) curl_perform = Module.findExportByName(null, 'curl_easy_perform');
    if (curl_perform) {
        Interceptor.attach(curl_perform, {
            onEnter: function (args) {
                log('CURL', 'curl_easy_perform called');
            },
            onLeave: function (retval) {
                log('CURL', 'curl_easy_perform returned: ' + retval);
            }
        });
        log('HOOK', 'curl_easy_perform hooked');
    }

    // Hook JNI NewStringUTF to capture ALL native->Java strings
    try {
        var env = Java.vm.getEnv();
        var vtable = env.handle.readPointer();
        // NewStringUTF is at vtable index 169
        var nsu = vtable.add(169 * Process.pointerSize).readPointer();
        Interceptor.attach(nsu, {
            onEnter: function (args) {
                try {
                    var s = args[1].readUtf8String();
                    if (s && s.length > 3) {
                        // Filter for interesting strings
                        var sl = s.toLowerCase();
                        if (sl.indexOf('http') !== -1 || sl.indexOf('key') !== -1 ||
                            sl.indexOf('token') !== -1 || sl.indexOf('auth') !== -1 ||
                            sl.indexOf('bearer') !== -1 || sl.indexOf('sign') !== -1 ||
                            sl.indexOf('api') !== -1 || sl.indexOf('gate') !== -1 ||
                            sl.indexOf('endpoint') !== -1 || sl.indexOf('url') !== -1 ||
                            sl.indexOf('elliot') !== -1 || sl.indexOf('ai.') !== -1 ||
                            s.length > 20) {
                            log('JNI_OUT', 'NewStringUTF: "' + s.substring(0, 500) + '"');
                            captured.nativeStrings.push(s);
                        }
                    }
                } catch (e) {}
            }
        });
        log('HOOK', 'JNI NewStringUTF hooked');
    } catch (e) {
        log('ERR', 'NewStringUTF hook: ' + e);
    }
}

// Start native hooks after a short delay to let .so load
setTimeout(setupNativeHooks, 2000);

// =====================================================
// PHASE 5: Summary dumper (runs after 30s)
// =====================================================

setTimeout(function () {
    log('=== SUMMARY ===', '');
    log('SUMMARY', 'Captured keys: ' + JSON.stringify(captured.keys));
    log('SUMMARY', 'Captured URLs: ' + JSON.stringify(captured.urls));
    log('SUMMARY', 'Captured auth headers: ' + JSON.stringify(captured.headers));
    log('SUMMARY', 'Native strings count: ' + captured.nativeStrings.length);

    // Print unique native strings that look like keys/tokens
    var seen = {};
    captured.nativeStrings.forEach(function (s) {
        if (!seen[s] && s.length > 10) {
            seen[s] = true;
            log('NATIVE_STR', s);
        }
    });
}, 30000);

log('INIT', 'Tartarus hook script loaded. Waiting for app activity...');
