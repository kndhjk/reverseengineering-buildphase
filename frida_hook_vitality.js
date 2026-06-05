'use strict';
/**
 * Frida hook for Vitality APK (nz.ac.auckland.se702.reverseai)
 *
 * Goal: Extract the real API key. The app uses native crypto
 * (libreverseai-crypto.so + libreverseai-core.so) with AES-GCM,
 * HMAC-SHA256, and install tokens. The key is derived at runtime
 * by NativeAuthBridge._z05().
 *
 * Hooks:
 *  1. Anti-tamper bypass (integrity checks, debugger detection)
 *  2. SSL pinning bypass (certificate pinning)
 *  3. NativeAuthBridge._z05() - capture the auth token output
 *  4. Crypto operations (SecretKeySpec, Cipher, Mac, MessageDigest)
 *  5. SharedPreferences monitoring (v_p1: vkb, vit, _p52)
 *  6. OkHttp network interception (Authorization header)
 *  7. JNI NewStringUTF for native string capture
 *  8. Base64 encode/decode monitoring
 */

var captured = {
    keys: [],
    authHeaders: [],
    nativeStrings: [],
    spValues: {},
    cryptoOps: []
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
// PHASE 1: Anti-Tamper Bypass
// =====================================================

Java.perform(function () {
    log('INIT', 'Java.perform started for Vitality');

    // Bypass Debug checks
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () { return false; };
        Debug.waitForDebugger.implementation = function () { };
        log('HOOK', 'Debug checks bypassed');
    } catch (e) {}

    // Bypass integrity check classes (X5.i, G4.e, F0.f)
    // These methods return boolean - return true to indicate "integrity OK"
    try {
        var X5 = Java.use('X5');
        X5.i.implementation = function () {
            log('BYPASS', 'X5.i() integrity check -> true');
            return true;
        };
        log('HOOK', 'X5.i bypassed');
    } catch (e) {
        log('ERR', 'X5.i: ' + e);
    }

    try {
        var G4 = Java.use('G4');
        G4.e.implementation = function () {
            log('BYPASS', 'G4.e() integrity check -> true');
            return true;
        };
        log('HOOK', 'G4.e bypassed');
    } catch (e) {
        log('ERR', 'G4.e: ' + e);
    }

    try {
        var F0 = Java.use('F0');
        F0.f.implementation = function () {
            log('BYPASS', 'F0.f() integrity check -> true');
            return true;
        };
        log('HOOK', 'F0.f bypassed');
    } catch (e) {
        log('ERR', 'F0.f: ' + e);
    }

    // =====================================================
    // PHASE 2: SSL Pinning Bypass
    // =====================================================

    // Replace TrustManager to accept all certificates
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'bypass.VitalityTM',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            return this.init(km, [TrustManager.$new()], sr);
        };
        log('HOOK', 'TrustManager bypass OK');
    } catch (e) {
        log('ERR', 'TrustManager bypass: ' + e);
    }

    // Bypass HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');
        var Verifier = Java.registerClass({
            name: 'bypass.VitalityHV',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });
        // Hook HttpsURLConnection.setHostnameVerifier
        var HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsConn.setDefaultHostnameVerifier.implementation = function (verifier) {
            log('BYPASS', 'setDefaultHostnameVerifier intercepted');
            return this.setDefaultHostnameVerifier(Verifier.$new());
        };
        HttpsConn.setHostnameVerifier.implementation = function (verifier) {
            log('BYPASS', 'setHostnameVerifier intercepted');
            return this.setHostnameVerifier(Verifier.$new());
        };
        log('HOOK', 'HostnameVerifier bypass OK');
    } catch (e) {
        log('ERR', 'HostnameVerifier: ' + e);
    }

    // =====================================================
    // PHASE 3: NativeAuthBridge - THE KEY TARGET
    // =====================================================

    try {
        var NAB = Java.use('nz.ac.auckland.se702.reverseai.security.NativeAuthBridge');

        // Hook _z05 - this is the native method that builds the auth token
        // Signature: _z05([B [B [B)String
        // Params: install token bytes, install time bytes(?), HMAC blob bytes
        // Returns: the authorization token string
        NAB._z05.implementation = function (a, b, c) {
            var result = this._z05(a, b, c);
            log('AUTH_TOKEN', '_z05() returned: "' + result + '"');
            captured.keys.push({method: '_z05', value: result});

            // Also log the inputs
            if (a) log('AUTH_INPUT', '_z05 arg0 (token): ' + hexEncode(a, 64));
            if (b) log('AUTH_INPUT', '_z05 arg1: ' + hexEncode(b, 64));
            if (c) log('AUTH_INPUT', '_z05 arg2 (hmac): ' + hexEncode(c, 64));

            return result;
        };
        log('HOOK', 'NativeAuthBridge._z05 hooked');

        // Hook _z06 - processes auth response
        NAB._z06.implementation = function (a) {
            log('AUTH', '_z06() called with: ' + hexEncode(a, 128));
            return this._z06(a);
        };
        log('HOOK', 'NativeAuthBridge._z06 hooked');

        // Call _y01, _y02, _y03 to see what data feeds into _z05
        try {
            var y01 = NAB._y01();
            log('AUTH_DATA', '_y01() install token: ' + hexEncode(y01, 64) + ' (len=' + (y01 ? y01.length : 0) + ')');
        } catch (e) {
            log('ERR', '_y01: ' + e);
        }

        try {
            var y02 = NAB._y02();
            log('AUTH_DATA', '_y02() install time: ' + y02);
        } catch (e) {
            log('ERR', '_y02: ' + e);
        }

        try {
            var y03 = NAB._y03();
            log('AUTH_DATA', '_y03() HMAC blob: ' + hexEncode(y03, 64) + ' (len=' + (y03 ? y03.length : 0) + ')');
        } catch (e) {
            log('ERR', '_y03: ' + e);
        }

    } catch (e) {
        log('ERR', 'NativeAuthBridge: ' + e);
    }

    // =====================================================
    // PHASE 4: Crypto Operations Capture
    // =====================================================

    // SecretKeySpec - capture all key material
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
            var hex = hexEncode(keyBytes, 64);
            log('CRYPTO', 'SecretKeySpec algo=' + algo + ' len=' + keyBytes.length + ' hex=' + hex);
            captured.cryptoOps.push({type: 'SecretKeySpec', algo: algo, hex: hex});
            return this.$init(keyBytes, algo);
        };
        SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (keyBytes, offset, len, algo) {
            var hex = '';
            for (var i = offset; i < Math.min(offset + len, offset + 64); i++) {
                hex += ('0' + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
            }
            log('CRYPTO', 'SecretKeySpec algo=' + algo + ' len=' + len + ' hex=' + hex);
            return this.$init(keyBytes, offset, len, algo);
        };
        log('HOOK', 'SecretKeySpec hooked');
    } catch (e) {
        log('ERR', 'SecretKeySpec: ' + e);
    }

    // Cipher - AES-GCM operations
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
            var modeStr = (mode === 1) ? 'ENCRYPT' : (mode === 2) ? 'DECRYPT' : 'MODE_' + mode;
            log('CRYPTO', 'Cipher.init mode=' + modeStr + ' algo=' + this.getAlgorithm());
            try {
                var keyBytes = key.getEncoded();
                if (keyBytes) {
                    log('CRYPTO', 'Cipher key: ' + hexEncode(keyBytes, 64));
                }
            } catch (e) {}
            if (params) {
                try {
                    var GCMParameterSpec = Java.use('javax.crypto.spec.GCMParameterSpec');
                    if (params instanceof GCMParameterSpec) {
                        var iv = params.getIV();
                        log('CRYPTO', 'GCM IV: ' + hexEncode(iv, 32) + ' tagLen=' + params.getTLen());
                    }
                } catch (e) {}
            }
            return this.init(mode, key, params);
        };

        Cipher.doFinal.overload('[B').implementation = function (input) {
            log('CRYPTO', 'Cipher.doFinal input_len=' + input.length);
            var result = this.doFinal(input);
            log('CRYPTO', 'Cipher.doFinal output_len=' + result.length + ' output=' + hexEncode(result, 64));
            return result;
        };
        log('HOOK', 'Cipher hooked');
    } catch (e) {
        log('ERR', 'Cipher: ' + e);
    }

    // Mac - HMAC operations
    try {
        var Mac = Java.use('javax.crypto.Mac');
        Mac.init.overload('java.security.Key').implementation = function (key) {
            try {
                var keyBytes = key.getEncoded();
                log('CRYPTO', 'Mac.init algo=' + this.getAlgorithm() + ' key=' + hexEncode(keyBytes, 64));
            } catch (e) {}
            return this.init(key);
        };
        Mac.doFinal.overload('[B').implementation = function (input) {
            var result = this.doFinal(input);
            log('CRYPTO', 'Mac.doFinal algo=' + this.getAlgorithm() + ' result=' + hexEncode(result, 32));
            return result;
        };
        log('HOOK', 'Mac hooked');
    } catch (e) {
        log('ERR', 'Mac: ' + e);
    }

    // MessageDigest - hash operations
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function (input) {
            var result = this.digest(input);
            log('CRYPTO', 'MessageDigest algo=' + this.getAlgorithm() + ' input_len=' + input.length + ' result=' + hexEncode(result, 32));
            return result;
        };
        log('HOOK', 'MessageDigest hooked');
    } catch (e) {
        log('ERR', 'MessageDigest: ' + e);
    }

    // =====================================================
    // PHASE 5: SharedPreferences Monitoring
    // =====================================================

    try {
        var SP = Java.use('android.app.SharedPreferencesImpl');
        SP.getString.implementation = function (key, def) {
            var val = this.getString(key, def);
            // Monitor all keys in v_p1 prefs
            if (key && (key === 'vkb' || key === 'vit' || key === '_p52' || key === 't1' ||
                        key === 'vitm' || key.indexOf('key') !== -1 || key.indexOf('token') !== -1)) {
                log('SP', 'getString("' + key + '") = "' + (val ? val.substring(0, 200) : 'null') + '"');
                captured.spValues[key] = val;
            }
            return val;
        };
        SP.putString.implementation = function (key, value) {
            if (key && (key === 'vkb' || key === 'vit' || key === '_p52' || key === 't1' ||
                        key === 'vitm' || key.indexOf('key') !== -1 || key.indexOf('token') !== -1)) {
                log('SP', 'putString("' + key + '") = "' + (value ? value.substring(0, 200) : 'null') + '"');
                captured.spValues[key] = value;
            }
            return this.putString(key, value);
        };
        log('HOOK', 'SharedPreferences hooked');
    } catch (e) {
        log('ERR', 'SharedPreferences: ' + e);
    }

    // =====================================================
    // PHASE 6: Network Interception
    // =====================================================

    // OkHttp RealCall interception
    try {
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.getResponseWithInterceptorChain.implementation = function () {
            log('HTTP', 'RealCall executing');
            var req = this.request();
            if (req) {
                var url = req.url().toString();
                log('HTTP', 'Request URL: ' + url);
                var headers = req.headers();
                for (var i = 0; i < headers.size(); i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    log('HTTP', 'Header: ' + name + ' = ' + value);
                    if (name.toLowerCase() === 'authorization') {
                        log('AUTH_HEADER', 'Authorization: ' + value);
                        captured.authHeaders.push(value);
                    }
                }
            }
            return this.getResponseWithInterceptorChain();
        };
        log('HOOK', 'OkHttp RealCall hooked');
    } catch (e) {
        log('ERR', 'RealCall: ' + e);
    }

    // Alternative: hook addHeader on Request.Builder
    try {
        var ReqBuilder = Java.use('okhttp3.Request$Builder');
        ReqBuilder.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function (name, value) {
            log('HTTP', 'addHeader: ' + name + ' = ' + value);
            if (name.toLowerCase() === 'authorization') {
                log('AUTH_HEADER', 'Authorization: ' + value);
                captured.authHeaders.push(value);
            }
            return this.addHeader(name, value);
        };
        log('HOOK', 'Request.Builder.addHeader hooked');
    } catch (e) {
        log('ERR', 'Request.Builder: ' + e);
    }

    // =====================================================
    // PHASE 7: Base64 Monitoring
    // =====================================================

    try {
        var Base64 = Java.use('android.util.Base64');
        Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
            var result = this.encodeToString(input, flags);
            if (input.length >= 16) {
                log('BASE64', 'encode len=' + input.length + ' hex=' + hexEncode(input, 32) + ' -> ' + result.substring(0, 60));
            }
            return result;
        };
        Base64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
            var result = this.decode(str, flags);
            if (result.length >= 16) {
                log('BASE64', 'decode "' + str.substring(0, 40) + '" -> len=' + result.length + ' hex=' + hexEncode(result, 32));
            }
            return result;
        };
        log('HOOK', 'Base64 hooked');
    } catch (e) {
        log('ERR', 'Base64: ' + e);
    }

    // =====================================================
    // PHASE 8: AES KeyStore Operations (X5 class)
    // =====================================================

    try {
        var X5 = Java.use('X5');

        // X5.b() - AES-GCM encrypt
        X5.b.overload('[B').implementation = function (input) {
            log('X5', 'b() encrypt input_len=' + input.length + ' input=' + hexEncode(input, 32));
            var result = this.b(input);
            log('X5', 'b() encrypt output_len=' + result.length + ' output=' + hexEncode(result, 32));
            return result;
        };

        // X5.a() - AES-GCM decrypt
        X5.a.overload('[B').implementation = function (input) {
            log('X5', 'a() decrypt input_len=' + input.length + ' input=' + hexEncode(input, 32));
            var result = this.a(input);
            log('X5', 'a() decrypt output_len=' + result.length + ' output=' + hexEncode(result, 32));
            return result;
        };

        // X5.f() - key blob storage/retrieval
        X5.f.implementation = function () {
            var result = this.f();
            log('X5', 'f() key blob: ' + hexEncode(result, 64) + ' (len=' + (result ? result.length : 0) + ')');
            captured.keys.push({method: 'X5.f', value: hexEncode(result, 128)});
            return result;
        };

        log('HOOK', 'X5 (AES KeyStore) hooked');
    } catch (e) {
        log('ERR', 'X5: ' + e);
    }

    // =====================================================
    // PHASE 9: F0 HMAC Operations
    // =====================================================

    try {
        var F0 = Java.use('F0');
        F0.a.overload('[B', 'long').implementation = function (key, timestamp) {
            var result = this.a(key, timestamp);
            log('F0', 'a() HMAC key=' + hexEncode(key, 32) + ' ts=' + timestamp + ' result=' + hexEncode(result, 16));
            return result;
        };
        log('HOOK', 'F0 (HMAC) hooked');
    } catch (e) {
        log('ERR', 'F0: ' + e);
    }

    // =====================================================
    // PHASE 10: G4 Install Token
    // =====================================================

    try {
        var G4 = Java.use('G4');
        G4.b.implementation = function () {
            var result = this.b();
            log('G4', 'b() install token: ' + hexEncode(result, 64) + ' (len=' + (result ? result.length : 0) + ')');
            return result;
        };
        G4.a.implementation = function () {
            var result = this.a();
            log('G4', 'a() install time: ' + result);
            return result;
        };
        log('HOOK', 'G4 (install token) hooked');
    } catch (e) {
        log('ERR', 'G4: ' + e);
    }

    // =====================================================
    // PHASE 11: JNI NewStringUTF
    // =====================================================

    try {
        var env = Java.vm.getEnv();
        var vtable = env.handle.readPointer();
        var nsu = vtable.add(169 * Process.pointerSize).readPointer();
        Interceptor.attach(nsu, {
            onEnter: function (args) {
                try {
                    var s = args[1].readUtf8String();
                    if (s && s.length > 5) {
                        var sl = s.toLowerCase();
                        if (sl.indexOf('bearer') !== -1 || sl.indexOf('authorization') !== -1 ||
                            sl.indexOf('key') !== -1 || sl.indexOf('token') !== -1 ||
                            sl.indexOf('auth') !== -1 || sl.indexOf('sign') !== -1 ||
                            sl.indexOf('http') !== -1 || sl.indexOf('api') !== -1 ||
                            sl.indexOf('elliot') !== -1 || s.length > 30) {
                            log('JNI_OUT', 'NewStringUTF: "' + s.substring(0, 500) + '"');
                            captured.nativeStrings.push(s);
                        }
                    }
                } catch (e) {}
            }
        });
        log('HOOK', 'JNI NewStringUTF hooked');
    } catch (e) {
        log('ERR', 'NewStringUTF: ' + e);
    }

    log('INIT', 'All Vitality hooks installed');
});

// =====================================================
// PHASE 12: Native lib hooks
// =====================================================

function setupNativeHooks() {
    var lib = null;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name === 'libreverseai-crypto.so' || mods[i].name === 'libreverseai-core.so') {
            lib = mods[i];
            break;
        }
    }
    if (!lib) {
        log('NATIVE', 'Native libs not loaded yet, retrying...');
        setTimeout(setupNativeHooks, 1000);
        return;
    }
    log('NATIVE', 'Found native lib: ' + lib.name + ' at ' + lib.base);

    // Enumerate exports looking for key-related functions
    var exports = lib.enumerateExports();
    log('NATIVE', 'Export count: ' + exports.length);
    exports.forEach(function (exp) {
        var name = exp.name.toLowerCase();
        if (name.indexOf('key') !== -1 || name.indexOf('auth') !== -1 ||
            name.indexOf('token') !== -1 || name.indexOf('encrypt') !== -1 ||
            name.indexOf('decrypt') !== -1 || name.indexOf('sign') !== -1 ||
            name.indexOf('derive') !== -1 || name.indexOf('hmac') !== -1 ||
            name.indexOf('z05') !== -1 || name.indexOf('z06') !== -1) {
            log('NATIVE', 'Interesting export: ' + exp.name + ' type=' + exp.type + ' addr=' + exp.address);

            // Try to hook it
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function (args) {
                        log('NATIVE_CALL', exp.name + ' called');
                        // Try to read first few args as pointers/strings
                        for (var a = 0; a < 4; a++) {
                            try {
                                var ptr = args[a];
                                if (!ptr.isNull() && ptr.toInt32() > 0x1000) {
                                    try {
                                        var s = ptr.readUtf8String(128);
                                        if (s && s.length > 3 && s.length < 500) {
                                            log('NATIVE_ARG', exp.name + ' arg' + a + ' = "' + s + '"');
                                        }
                                    } catch (e2) {
                                        log('NATIVE_ARG', exp.name + ' arg' + a + ' = ' + ptr);
                                    }
                                }
                            } catch (e3) {}
                        }
                    },
                    onLeave: function (retval) {
                        if (!retval.isNull()) {
                            try {
                                var s = retval.readUtf8String(256);
                                if (s && s.length > 3) {
                                    log('NATIVE_RET', exp.name + ' returned: "' + s + '"');
                                }
                            } catch (e) {
                                log('NATIVE_RET', exp.name + ' returned ptr: ' + retval);
                            }
                        }
                    }
                });
            } catch (e) {
                log('ERR', 'Hook ' + exp.name + ': ' + e);
            }
        }
    });
}

setTimeout(setupNativeHooks, 2000);

// =====================================================
// Summary after 35 seconds
// =====================================================

setTimeout(function () {
    log('=== SUMMARY ===', '');
    log('SUMMARY', 'Captured API keys/tokens: ' + JSON.stringify(captured.keys));
    log('SUMMARY', 'Auth headers: ' + JSON.stringify(captured.authHeaders));
    log('SUMMARY', 'SharedPreferences values: ' + JSON.stringify(captured.spValues));
    log('SUMMARY', 'Crypto operations: ' + captured.cryptoOps.length);

    var seen = {};
    captured.nativeStrings.forEach(function (s) {
        if (!seen[s] && s.length > 10) {
            seen[s] = true;
            log('NATIVE_STR', s);
        }
    });
}, 35000);

log('INIT', 'Vitality hook script loaded. Waiting for app activity...');
