/**
 * Script injected by the WebView to override navigator.credentials and call the
 * Android WebMessageListener bridge instead.
 *
 * JAVASCRIPT_BRIDGE is replaced at injection time with the actual bridge name
 * registered via WebViewCompat.addWebMessageListener().
 *
 * Communication uses postMessage() / onmessage instead of direct Java-object
 * method invocation, ensuring that only the registered frame and origin can
 * interact with the bridge.
 */

// Defense-in-depth: refuse to run in sub-frames.
// The primary enforcement is on the Java side (isMainFrame check in FidoMessageBridge),
// but this prevents the polyfill from even overriding navigator.credentials in iframes.
if (window !== window.top) {
    console.error('FIDO bridge: sub-frame detected, not injecting.')
    throw new Error('FIDO WebAuthn bridge is not available in sub-frames')
}

// check if replaced in Android: if not defined, throws a 'ReferenceError'.
JAVASCRIPT_BRIDGE

var __fido_promise_cache__ = {}

// Listen for responses from the Java bridge delivered via JavaScriptReplyProxy
JAVASCRIPT_BRIDGE.onmessage = function(event) {
    var data
    try {
        data = JSON.parse(event.data)
    } catch(e) {
        console.error('FIDO bridge: failed to parse response: ', e.message)
        return
    }

    var uuid = data.promiseUuid
    if (!uuid || !(uuid in __fido_promise_cache__)) {
        console.error('FIDO bridge: unknown or missing promiseUuid in response:', uuid)
        return
    }

    var promise = __fido_promise_cache__[uuid]

    delete __fido_promise_cache__[uuid]

    if (data.type === 'resolve') {
        console.log('Promise resolved:', promise.method, uuid)
        var result = __decode__credentials(data.result)
        promise.resolve(result)
    } else if (data.type === 'reject') {
        console.log('Promise rejected:', promise.method, uuid, data.message)
        promise.reject(new DOMException(data.message, 'NotAllowedError'))
    } else {
        console.error('FIDO bridge: unknown response type:', data.type)
        promise.reject(new DOMException('The operation failed', 'NotAllowedError'))
    }
}

// override functions on navigator
function overrideNavigatorCredentialsWithBridgeCall(method) {
    navigator.credentials[method] = (options) => {
      var uuid = crypto.randomUUID()

      var promise = new Promise((resolve, reject) => {
        __fido_promise_cache__[uuid] = {'resolve':resolve, 'reject':reject, 'method': method}

        // Use a custom replacer to automatically base64url-encode any binary
        // values (Uint8Array / ArrayBuffer) during serialization. This avoids
        // having to explicitly enumerate every field that may contain binary data.
        var options_json = JSON.stringify(options, function(key, value) {
            if (value instanceof Uint8Array) {
                return __encode(value)
            } else if (value instanceof ArrayBuffer) {
                return __encode(new Uint8Array(value))
            }
            return value
        }, 4)

        console.log('options:', options_json)

        // Send request to the Java bridge via postMessage
        try {
            JAVASCRIPT_BRIDGE.postMessage(JSON.stringify({
                method: method,
                promiseUuid: uuid,
                options: options_json
            }))
        } catch(e) {
            delete __fido_promise_cache__[uuid]
            console.error('FIDO bridge: postMessage failed:', e)
            reject(new DOMException('The operation failed', 'NotAllowedError'))
        }
      })

      return promise
    }
}

function __encode(buffer) {
    return btoa(
        Array.from(
            new Uint8Array(buffer),
            function (b) {
                return String.fromCharCode(b);
            }
        ).join('')
    ).replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function __decode(value) {
    var m = value.length % 4;

    return Uint8Array
        .from(
            atob(
                value
                    .replace(/-/g, '+')
                    .replace(/_/g, '/')
                    .padEnd(
                        value.length + (m === 0 ? 0 : 4 - m), '='
                    )
            ),
            function (c) {
                return c.charCodeAt(0)
            }
        )
        .buffer;
}

function __decode__credentials(result) {
    result.rawId = __decode(result.rawId);
    result.response.clientDataJSON = __decode(result.response.clientDataJSON);
    if (result.response.hasOwnProperty('publicKey')) {
        result.response.publicKey = __decode(result.response.publicKey);
    }
    if (result.response.hasOwnProperty('attestationObject')) {
        result.response.attestationObject = __decode(result.response.attestationObject);
    }
    if (result.response.hasOwnProperty('authenticatorData')) {
        result.response.authenticatorData = __decode(result.response.authenticatorData);
    }
    if (result.response.hasOwnProperty('signature')) {
        result.response.signature = __decode(result.response.signature);
    }
    if (result.response.hasOwnProperty('userHandle')) {
        result.response.userHandle = __decode(result.response.userHandle);
    }

    if (result.hasOwnProperty('clientExtensionResults') && result.clientExtensionResults) {
        if (result.clientExtensionResults.hasOwnProperty('prf') &&
            result.clientExtensionResults.prf.hasOwnProperty('results')) {
            if(result.clientExtensionResults.prf.results.hasOwnProperty('first')) {
                result.clientExtensionResults.prf.results.first = __decode(
                    result.clientExtensionResults.prf.results.first
                );
            }

            if(result.clientExtensionResults.prf.results.hasOwnProperty('second')) {
                result.clientExtensionResults.prf.results.second = __decode(
                    result.clientExtensionResults.prf.results.second
                );
            }
        }

        if (result.clientExtensionResults.hasOwnProperty('largeBlob')) {
            if (result.clientExtensionResults.largeBlob.hasOwnProperty('blob')) {
                result.clientExtensionResults.largeBlob.blob = __decode(
                    result.clientExtensionResults.largeBlob.blob
                );
            }
        }

        // sign extension v3 https://yubicolabs.github.io/webauthn-sign-extension/3/#sctn-sign-extension
        if (result.clientExtensionResults.hasOwnProperty('sign')) {
            if (result.clientExtensionResults.sign.hasOwnProperty('generatedKey')) {
                if (result.clientExtensionResults.sign.generatedKey.hasOwnProperty('publicKey')) {
                    result.clientExtensionResults.sign.generatedKey.publicKey =
                        __decode(result.clientExtensionResults.sign.generatedKey.publicKey);
                }
                if (result.clientExtensionResults.sign.generatedKey.hasOwnProperty('attestationObject')) {
                    result.clientExtensionResults.sign.generatedKey.attestationObject =
                        __decode(result.clientExtensionResults.sign.generatedKey.attestationObject);
                }
            }

            if (result.clientExtensionResults.sign.hasOwnProperty('signature')) {
                result.clientExtensionResults.sign.signature = __decode(
                    result.clientExtensionResults.sign.signature
                );
            }
        }
    }

    // augment pure json result with functions needed by PublicKeyCredential
    result.getClientExtensionResults = () => result.clientExtensionResults
    result.response.getTransports = () => result.response.transports

    return result
}


overrideNavigatorCredentialsWithBridgeCall("create")
overrideNavigatorCredentialsWithBridgeCall("get")

// Replace the browser's PublicKeyCredential with a bare constructor so we can
// attach our own static feature-detection methods below.
window.PublicKeyCredential = (function () { });

// Returns false: this WebView bridge uses an external hardware authenticator
// (e.g. YubiKey), not a built-in platform authenticator (Face ID, fingerprint, etc.).
// Note: some relying parties misuse this check as a general "is WebAuthn available?"
// gate and may fall back to passwords when it returns false.
window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
    function () {
        return Promise.resolve(false);
    };

// Returns false: conditional mediation (passkey autofill UI) is not supported
// in this WebView bridge. Without this override, calling the method would throw
// a TypeError since the original PublicKeyCredential was replaced above.
window.PublicKeyCredential.isConditionalMediationAvailable =
    function () {
        return Promise.resolve(false);
    };

// Returns true: this bridge exists specifically to support external CTAP2
// security keys. Some Chromium-based sites check this non-standard method
// for feature detection.
window.PublicKeyCredential.isExternalCTAP2SecurityKeySupported =
    function () {
        return Promise.resolve(true);
    };

console.debug('FIDO WebAuthn bridge injected!')