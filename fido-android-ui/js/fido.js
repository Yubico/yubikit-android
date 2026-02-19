/**
 * Script injected by the WebView to override navigator.credentials and call the
 * Android JavascriptInterface bridge instead.
 *
 * JAVASCRIPT_BRIDGE is replaced at injection time with the actual bridge name.
 */

// check if replaced in Android: if not defined, throws a 'ReferenceError'.
JAVASCRIPT_BRIDGE

JAVASCRIPT_BRIDGE.__injected__ = true
JAVASCRIPT_BRIDGE.__promise_cache__ = {}

// override functions on navigator
function overrideNavigatorCredentialsWithBridgeCall(method) {
    navigator.credentials[method] = (options) => {
      var uuid = crypto.randomUUID()

      var promise = new Promise((resolve, reject) => {
        JAVASCRIPT_BRIDGE.__promise_cache__[uuid] = {'resolve':resolve, 'reject':reject, 'method': method}

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

        console.debug('options:', options_json)
        JAVASCRIPT_BRIDGE[method](uuid, options_json)
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

JAVASCRIPT_BRIDGE.__resolve__ = (uuid, result) => {
    if (uuid in JAVASCRIPT_BRIDGE.__promise_cache__) {
        var promise = JAVASCRIPT_BRIDGE.__promise_cache__[uuid]
        console.log("Promise resolved:", promise.method, uuid)

        result = __decode__credentials(result)

        JAVASCRIPT_BRIDGE.__promise_cache__[uuid].resolve(result)

        delete JAVASCRIPT_BRIDGE.__promise_cache__[uuid]
    } else {
        console.error("Promise with id", uuid, "does not exist. Not resolving unknown promise.")
    }
}

JAVASCRIPT_BRIDGE.__reject__ = (uuid, result) => {
    if (uuid in JAVASCRIPT_BRIDGE.__promise_cache__) {
        var promise = JAVASCRIPT_BRIDGE.__promise_cache__[uuid]
        console.log("Rejected promise", JSON.stringify(promise), "with uuid", uuid, "and result", result)

        JAVASCRIPT_BRIDGE.__promise_cache__[uuid].reject(new DOMException(result, 'NotAllowedError'))
        delete JAVASCRIPT_BRIDGE.__promise_cache__[uuid]
    } else {
        console.error("Promise with id", uuid, "does not exist. Not rejecting unknown promise.")
    }
}

overrideNavigatorCredentialsWithBridgeCall("create")
overrideNavigatorCredentialsWithBridgeCall("get")

window.PublicKeyCredential = (function () { });
window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
    function () {
        return Promise.resolve(false);
    };

console.debug('FIDO WebAuthn bridge injected!')