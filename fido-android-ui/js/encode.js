// This is the JS that is injected into the web.
// Modifying this will modify the communication between the phone app and the
// web app.
var __webauthn_interface__;
var __webauthn_hooks__;
(function (__webauthn_hooks__) {
    console.log("In the hook.");

    const stringifyBinary = (key, value) => {
      if (value instanceof Uint8Array) {
        return CM_base64url_encode(value);
      } else if (value instanceof ArrayBuffer) {
        return CM_base64url_encode(new Uint8Array(value));
      } else {
        return value;
      }
    };

    const stringify = (data) => {
      return JSON.stringify(data, stringifyBinary);
    };

    //Adding event listener to the interface for replies by default
    __webauthn_interface__.addEventListener('message', onReply);
    // pendingResolveGet/Create is the thunk to resolve an outstanding get request.
    var pendingResolveGet = null;
    var pendingResolveCreate = null;
    // pendingRejectGet/Create is the thunk to fail an outstanding request.
    var pendingRejectGet = null;
    var pendingRejectCreate = null;
    // create overrides 'navigator.credentials.create' which proxies webauthn requests
    // to the create embedder
    function create(request) {
        if (!("publicKey" in request)) {
            return __webauthn_hooks__.originalCreateFunction(request);
        }
        var ret = new Promise(function (resolve, reject) {
            pendingResolveCreate = resolve;
            pendingRejectCreate = reject;
        });
        var temppk = request.publicKey;
        if (temppk.hasOwnProperty('challenge')) {
            var str = CM_base64url_encode(temppk.challenge);
            temppk.challenge = str;
        }
        if (temppk.hasOwnProperty('user') && temppk.user.hasOwnProperty('id')) {
            var encodedString = CM_base64url_encode(temppk.user.id);
            temppk.user.id = encodedString;
        }
        var jsonObj = {"type":"create", "request":temppk}

        var json = stringify(jsonObj);
        console.log("Post message: " + json);
        __webauthn_interface__.postMessage(json);
        return ret;
    }
    __webauthn_hooks__.create = create;
    // get overrides `navigator.credentials.get` and proxies any WebAuthn
    // requests to the get embedder.
    function get(request) {
        if (!("publicKey" in request)) {
            return __webauthn_hooks__.originalGetFunction(request);
        }
        var ret = new Promise(function (resolve, reject) {
            pendingResolveGet = resolve;
            pendingRejectGet = reject;
        });
        var temppk = request.publicKey;
        if (temppk.hasOwnProperty('challenge')) {
            var str = CM_base64url_encode(temppk.challenge);
            temppk.challenge = str;
        }
        var jsonObj = {"type":"get", "request":temppk}

        var json = stringify(jsonObj);
        __webauthn_interface__.postMessage(json);
        return ret;
    }
    __webauthn_hooks__.get = get;

    // The embedder gives replies back here, caught by the event listener.
    function onReply(msg) {
        var reply = JSON.parse(msg.data);
        var type = reply[2];
        console.log("Called onReply with " + msg);
        if(type === "get") {
            onReplyGet(reply);
        } else if (type === "create") {
            onReplyCreate(reply);
        } else {
            console.log("Incorrect response format for reply");
        }
    }

    // Resolves what is expected for get, called when the embedder is ready
    function onReplyGet(reply) {
        console.log("Received get reply: " + reply)
        if (pendingResolveGet === null || pendingRejectGet === null) {
            console.log("Reply failure: Resolve: " + pendingResolveCreate +
                    " and reject: " + pendingRejectCreate);
            return;
        }
        if (reply[0] != 'success') {
            var reject = pendingRejectGet;
            pendingResolveGet = null;
            pendingRejectGet = null;
            reject(new DOMException(reply[1], "NotAllowedError"));
            return;
        }
        console.log("Credential: " + reply[1])
        var cred = credentialManagerDecode(reply[1]);
        var resolve = pendingResolveGet;
        pendingResolveGet = null;
        pendingRejectGet = null;
        resolve(cred);
    }
    __webauthn_hooks__.onReplyGet = onReplyGet;
    // This a specific decoder for expected types contained in PublicKeyCredential json
    function CM_base64url_decode(value) {
        var m = value.length % 4;
        return Uint8Array.from(atob(value.replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(value.length + (m === 0 ? 0 : 4 - m), '=')), function (c)
            { return c.charCodeAt(0); }).buffer;
    }
    __webauthn_hooks__.CM_base64url_decode = CM_base64url_decode;
    function CM_base64url_encode(buffer) {
        return btoa(Array.from(new Uint8Array(buffer), function (b)
        { return String.fromCharCode(b); }).join(''))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+${'$'}/, '');
    }
    __webauthn_hooks__.CM_base64url_encode = CM_base64url_encode;
    // Resolves what is expected for create, called when the embedder is ready
    function onReplyCreate(reply) {
        console.log("Received create reply: " + reply)
        if (pendingResolveCreate === null || pendingRejectCreate === null) {
            return;
        }
        if (reply[0] != 'success') {
            var reject = pendingRejectCreate;
            pendingResolveCreate = null;
            pendingRejectCreate = null;
            reject(new DOMException(reply[1], "NotAllowedError"));
            return;
        }
        // console.log("Credential: " + reply[1])
        var cred = credentialManagerDecode(reply[1]);
        var resolve = pendingResolveCreate;
        pendingResolveCreate = null;
        pendingRejectCreate = null;
        resolve(cred);
    }
    __webauthn_hooks__.onReplyCreate = onReplyCreate;


    function recodeLargeBlob(value) {
        largeBlob = {}
        if (value.hasOwnProperty('blob')) {
            largeBlob['blob'] = CM_base64url_decode(value.blob);
        }
        if (value.hasOwnProperty('supported')) {
            largeBlob['supported'] = value.supported;
        }
        if (value.hasOwnProperty('written')) {
            largeBlob['written'] = value.written;
        }
        return largeBlob;
    }

    function recodePrf(value) {
        console.log("Recode prf input: " + stringify(value));
        recodedPrf = {}

        if (value.hasOwnProperty('enabled')) {
            recodedPrf['enabled'] = value['enabled'];
        }

        if (value.hasOwnProperty('results')) {
            resultsValue = {}
            if (value['results'].hasOwnProperty('first')) {
                resultsValue['first'] = CM_base64url_decode(value['results']['first']);
            }
            if (value['results'].hasOwnProperty('second')) {
                resultsValue['second'] = CM_base64url_decode(value['results']['second']);
            }
            recodedPrf['results'] = resultsValue;
        }

        console.log("Recode prf output: " + stringify(recodedPrf));
        return recodedPrf;
    }

    function recodeSign(value) {
        console.log("Recode sign input: " + stringify(value));
        recodedSign = {}

        if (value.hasOwnProperty('generatedKey')) {
            generatedKeyValue = {}
            if (value['generatedKey'].hasOwnProperty('publicKey')) {
                generatedKeyValue['publicKey'] = CM_base64url_decode(value['generatedKey']['publicKey']);
            }
            if (value['generatedKey'].hasOwnProperty('attestationObject')) {
                generatedKeyValue['attestationObject'] = CM_base64url_decode(value['generatedKey']['attestationObject']);
            }
            if (value['generatedKey'].hasOwnProperty('algorithm')) {
                generatedKeyValue['algorithm'] = value['generatedKey']['algorithm'];
            }
            recodedSign['generatedKey'] = generatedKeyValue;
        }

        if (value.hasOwnProperty('signature')) {
            recodedSign['signature'] = CM_base64url_decode(value['signature']);
        }

        console.log("Recode sign output: " + stringify(recodedSign));
        return recodedSign;
    }

    /**
     * This decodes the output from the credential manager flow to parse back into URL format. Both
     * get and create flows ultimately return a PublicKeyCredential object.
     * @param json_result
     */
    function credentialManagerDecode(decoded_reply) {
        decoded_reply.rawId = CM_base64url_decode(decoded_reply.rawId);
        decoded_reply.response.clientDataJSON = CM_base64url_decode(decoded_reply.response.clientDataJSON);
        console.log("response: " + stringify(decoded_reply.response));
        if (decoded_reply.response.hasOwnProperty('attestationObject')) {
            decoded_reply.response.attestationObject = CM_base64url_decode(decoded_reply.response.attestationObject);
        }
        if (decoded_reply.response.hasOwnProperty('authenticatorData')) {
            decoded_reply.response.authenticatorData = CM_base64url_decode(decoded_reply.response.authenticatorData);
        }
        if (decoded_reply.response.hasOwnProperty('signature')) {
            decoded_reply.response.signature = CM_base64url_decode(decoded_reply.response.signature);
        }
        if (decoded_reply.response.hasOwnProperty('userHandle')) {
            decoded_reply.response.userHandle = CM_base64url_decode(decoded_reply.response.userHandle);
        }
        decoded_reply.getClientExtensionResults = function getClientExtensionResults() {
            result = decoded_reply.hasOwnProperty('clientExtensionResults')
                ? decoded_reply.clientExtensionResults
                : {};

            dict = {};
            for(key in result) {
                if (result.hasOwnProperty(key)) {
                    if (key == "largeBlob") {
                        dict['largeBlob'] = recodeLargeBlob(result[key]);
                    } else if (key == "prf") {
                        dict['prf'] = recodePrf(result[key]);
                    } else if (key == "sign") {
                        dict['sign'] = recodeSign(result[key]);
                    } else {
                        dict[key] = result[key];
                    }
                }
            }
            console.log("Returning result: " + JSON.stringify(dict, stringifyBinary));
            return dict;
        }
        return decoded_reply;
    }
})(__webauthn_hooks__ || (__webauthn_hooks__ = {}));
__webauthn_hooks__.originalGetFunction = navigator.credentials.get;
__webauthn_hooks__.originalCreateFunction = navigator.credentials.create;
navigator.credentials.get = __webauthn_hooks__.get;
navigator.credentials.create = __webauthn_hooks__.create;
// Some sites test that `typeof window.PublicKeyCredential` is
// `function`.
window.PublicKeyCredential = (function () { });
window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
    function () {
        return Promise.resolve(false);
    };
