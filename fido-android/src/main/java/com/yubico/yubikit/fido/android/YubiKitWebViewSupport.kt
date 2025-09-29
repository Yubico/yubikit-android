/*
 * Copyright (C) 2025 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.fido.android

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.text.InputType
import android.webkit.HttpAuthHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.annotation.UiThread
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONArray
import org.json.JSONObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

fun WebView.withYubiKitWebauthn(
    coroutineScope: CoroutineScope,
    yubiKitFidoClient: YubiKitFidoClient
) = YubiKitWebViewSupport.withYubiKitWebauthn(this, coroutineScope, yubiKitFidoClient)


internal class YubiKitWebViewSupport {
    companion object {
        private val logger: Logger = LoggerFactory.getLogger(YubiKitWebViewSupport::class.java)

        @JvmStatic
        @SuppressLint("SetJavaScriptEnabled")
        fun withYubiKitWebauthn(
            webView: WebView,
            coroutineScope: CoroutineScope,
            yubiKitFidoClient: YubiKitFidoClient
        ) {
            this.apply {
                webView.settings.javaScriptEnabled = true
            }
            val webauthnListener =
                WebauthnListener(webView.context, coroutineScope, yubiKitFidoClient)
            val webViewClient = object : WebViewClient() {
                override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                    super.onPageStarted(view, url, favicon)
                    logger.trace("onPageStarted: {}", url)
                    logger.trace("userAgent: {}", view?.settings?.userAgentString)
                    webauthnListener.onPageStarted();
                    webView.evaluateJavascript(JS, null)
                }

                override fun onReceivedHttpAuthRequest(
                    view: WebView?,
                    handler: HttpAuthHandler?,
                    host: String?,
                    realm: String?
                ) {

                    if (handler == null || view == null) return
                    val context = view.context
                    coroutineScope.launch {
                        val (username, password) = getUserCredentialsDialog(context)
                        if (username != null && password != null) {
                            handler.proceed(username, password)
                        } else {
                            handler.cancel()
                        }
                    }
                }
            }

            val rules = setOf("*")
            if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                WebViewCompat.addWebMessageListener(
                    webView, INTERFACE_NAME,
                    rules, webauthnListener
                )
            }

            webView.webViewClient = webViewClient
        }

        @OptIn(ExperimentalCoroutinesApi::class)
        private suspend fun getUserCredentialsDialog(context: Context): Pair<String?, String?> =
            suspendCancellableCoroutine { cont ->
                val builder = AlertDialog.Builder(context)
                builder.setTitle("HTTP Authentication Required")
                val layout = LinearLayout(context)
                layout.orientation = LinearLayout.VERTICAL
                val paddingPx = (8 * context.resources.displayMetrics.density).toInt()
                layout.setPadding(paddingPx, paddingPx, paddingPx, paddingPx)

                val usernameInput = EditText(context)
                usernameInput.hint = "Username"
                layout.addView(usernameInput)

                val passwordInput = EditText(context)
                passwordInput.hint = "Password"
                passwordInput.inputType =
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                layout.addView(passwordInput)

                builder.setView(layout)
                builder.setPositiveButton("OK") { _, _ ->
                    cont.resume(
                        Pair(
                            usernameInput.text.toString(),
                            passwordInput.text.toString()
                        ),
                        null
                    )
                }
                builder.setNegativeButton("Cancel") { _, _ ->
                    cont.resume(Pair(null, null), null)
                }
                builder.setOnCancelListener {
                    cont.resume(Pair(null, null), null)
                }
                builder.show()
            }

        private const val INTERFACE_NAME = "__webauthn_interface__"
        private const val JS = """
            var __webauthn_interface__,__webauthn_hooks__;!function(e){console.log('In the hook.');let n=(e,n)=>n instanceof Uint8Array?u(n):n instanceof ArrayBuffer?u(new Uint8Array(n)):n,t=e=>JSON.stringify(e,n);__webauthn_interface__.addEventListener('message',function e(n){var t=JSON.parse(n.data),r=t[2];console.log('Called onReply with '+n),'get'===r?l(t):'create'===r?c(t):console.log('Incorrect response format for reply')});var r=null,a=null,o=null,s=null;function l(e){if(console.log('Received get reply: '+e),null===r||null===o){console.log('Reply failure: Resolve: '+a+' and reject: '+s);return}if('success'!=e[0]){var n=o;r=null,o=null,n(new DOMException(e[1],'NotAllowedError'));return}console.log('Credential: '+e[1]);var t=f(e[1]),l=r;r=null,o=null,l(t)}function i(e){var n=e.length%4;return Uint8Array.from(atob(e.replace(/-/g,'+').replace(/_/g,'/').padEnd(e.length+(0===n?0:4-n),'=')),function(e){return e.charCodeAt(0)}).buffer}function u(e){return btoa(Array.from(new Uint8Array(e),function(e){return String.fromCharCode(e)}).join('')).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+${'$'}/,'')}function c(e){if(console.log('Received create reply: '+e),null!==a&&null!==s){if('success'!=e[0]){var n=s;a=null,s=null,n(new DOMException(e[1],'NotAllowedError'));return}var t=f(e[1]),r=a;a=null,s=null,r(t)}}function p(e){return largeBlob={},e.hasOwnProperty('blob')&&(largeBlob.blob=i(e.blob)),e.hasOwnProperty('supported')&&(largeBlob.supported=e.supported),e.hasOwnProperty('written')&&(largeBlob.written=e.written),largeBlob}function g(e){return console.log('Recode prf input: '+t(e)),recodedPrf={},e.hasOwnProperty('enabled')&&(recodedPrf.enabled=e.enabled),e.hasOwnProperty('results')&&(resultsValue={},e.results.hasOwnProperty('first')&&(resultsValue.first=i(e.results.first)),e.results.hasOwnProperty('second')&&(resultsValue.second=i(e.results.second)),recodedPrf.results=resultsValue),console.log('Recode prf output: '+t(recodedPrf)),recodedPrf}function h(e){return console.log('Recode sign input: '+t(e)),recodedSign={},e.hasOwnProperty('generatedKey')&&(generatedKeyValue={},e.generatedKey.hasOwnProperty('publicKey')&&(generatedKeyValue.publicKey=i(e.generatedKey.publicKey)),e.generatedKey.hasOwnProperty('attestationObject')&&(generatedKeyValue.attestationObject=i(e.generatedKey.attestationObject)),e.generatedKey.hasOwnProperty('algorithm')&&(generatedKeyValue.algorithm=e.generatedKey.algorithm),recodedSign.generatedKey=generatedKeyValue),e.hasOwnProperty('signature')&&(recodedSign.signature=i(e.signature)),console.log('Recode sign output: '+t(recodedSign)),recodedSign}function f(e){return e.rawId=i(e.rawId),e.response.clientDataJSON=i(e.response.clientDataJSON),console.log('response: '+t(e.response)),e.response.hasOwnProperty('attestationObject')&&(e.response.attestationObject=i(e.response.attestationObject)),e.response.hasOwnProperty('authenticatorData')&&(e.response.authenticatorData=i(e.response.authenticatorData)),e.response.hasOwnProperty('signature')&&(e.response.signature=i(e.response.signature)),e.response.hasOwnProperty('userHandle')&&(e.response.userHandle=i(e.response.userHandle)),e.getClientExtensionResults=function t(){for(key in result=e.hasOwnProperty('clientExtensionResults')?e.clientExtensionResults:{},dict={},result)result.hasOwnProperty(key)&&('largeBlob'==key?dict.largeBlob=p(result[key]):'prf'==key?dict.prf=g(result[key]):'sign'==key?dict.sign=h(result[key]):dict[key]=result[key]);return console.log('Returning result: '+JSON.stringify(dict,n)),dict},e}e.create=function n(r){if(!('publicKey'in r))return e.originalCreateFunction(r);var o=new Promise(function(e,n){a=e,s=n}),l=r.publicKey;if(l.hasOwnProperty('challenge')){var i=u(l.challenge);l.challenge=i}if(l.hasOwnProperty('user')&&l.user.hasOwnProperty('id')){var c=u(l.user.id);l.user.id=c}var p=t({type:'create',request:l});return console.log('Post message: '+p),__webauthn_interface__.postMessage(p),o},e.get=function n(a){if(!('publicKey'in a))return e.originalGetFunction(a);var s=new Promise(function(e,n){r=e,o=n}),l=a.publicKey;if(l.hasOwnProperty('challenge')){var i=u(l.challenge);l.challenge=i}var c=t({type:'get',request:l});return __webauthn_interface__.postMessage(c),s},e.onReplyGet=l,e.CM_base64url_decode=i,e.CM_base64url_encode=u,e.onReplyCreate=c}(__webauthn_hooks__||(__webauthn_hooks__={})),__webauthn_hooks__.originalGetFunction=navigator.credentials.get,__webauthn_hooks__.originalCreateFunction=navigator.credentials.create,navigator.credentials.get=__webauthn_hooks__.get,navigator.credentials.create=__webauthn_hooks__.create,window.PublicKeyCredential=function(){},window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable=function(){return Promise.resolve(!1)};
        """
    }

    private class WebauthnListener(
        private val activity: Context,
        private val coroutineScope: CoroutineScope,
        private val yubiKitFidoClient: YubiKitFidoClient
    ) : WebViewCompat.WebMessageListener {

        /** havePendingRequest is true if there is an outstanding WebAuthn request. There is only ever
        one request outstanding at a time.*/
        private var havePendingRequest = false

        /** pendingRequestIsDoomed is true if the WebView has navigated since starting a request. The
        fido module cannot be cancelled, but the response will never be delivered in this case.*/
        private var pendingRequestIsDoomed = false

        /** replyChannel is the port that the page is listening for a response on. It
        is valid iff `havePendingRequest` is true.*/
        private var replyChannel: ReplyChannel? = null

        private val logger = LoggerFactory.getLogger(WebauthnListener::class.java)

        /** Called by the page when it wants to do a WebAuthn `get` or 'post' request. */
        @UiThread
        override fun onPostMessage(
            view: WebView,
            message: WebMessageCompat,
            sourceOrigin: Uri,
            isMainFrame: Boolean,
            replyProxy: JavaScriptReplyProxy,
        ) {
            logger.debug("In Post Message: {} source: {}", message, sourceOrigin)
            val messageData = message.data ?: return
            onRequest(messageData, sourceOrigin, isMainFrame, JavaScriptReplyChannel(replyProxy))
        }

        private fun onRequest(
            msg: String?,
            sourceOrigin: Uri,
            isMainFrame: Boolean,
            reply: ReplyChannel,
        ) {
            msg?.let {
                val jsonObj = JSONObject(msg)
                val type = jsonObj.getString(TYPE_KEY)
                val message = jsonObj.getString(REQUEST_KEY)

                val isCreate = type == CREATE_UNIQUE_KEY
                val isGet = type == GET_UNIQUE_KEY

                if (havePendingRequest) {
                    postErrorMessage(reply, "request already in progress", type)
                    return
                }
                replyChannel = reply
                if (!isMainFrame) {
                    reportFailure("requests from subframes are not supported", type)
                    return
                }
                val originScheme = sourceOrigin.scheme
                if (originScheme == null || originScheme.lowercase() != "https") {
                    reportFailure("WebAuthn not permitted for current URL", type)
                    return
                }

                havePendingRequest = true
                pendingRequestIsDoomed = false

                val replyCurrent = replyChannel
                if (replyCurrent == null) {
                    logger.error("reply channel was null, cannot continue")
                    return
                }

                this.coroutineScope.launch {
                    if (isCreate) {
                        handleCreateFlow(message, sourceOrigin, replyCurrent)
                    } else if (isGet) {
                        handleGetFlow(message, sourceOrigin, replyCurrent)
                    } else {
                        logger.error("Incorrect request json")
                    }
                }
            }
        }

        private suspend fun handleGetFlow(
            message: String,
            sourceOrigin: Uri,
            reply: ReplyChannel,
        ) {
            try {
                havePendingRequest = false
                pendingRequestIsDoomed = false

                val response = yubiKitFidoClient.getAssertion(
                    sourceOrigin.toString(),
                    message,
                    null
                ).fold(
                    onSuccess = {
                        it
                    },
                    onFailure = {
                        throw it
                    }
                )
                logger.trace("assertion: {}", response)
                val successArray = mutableListOf<Any>()
                successArray.add("success")
                successArray.add(JSONObject(response))
                successArray.add(GET_UNIQUE_KEY)
                reply.send(JSONArray(successArray).toString())
                replyChannel = null
            } catch (t: Throwable) {
                reportFailure("Error: ${t.message}", GET_UNIQUE_KEY)
            }
        }

        private suspend fun handleCreateFlow(
            message: String,
            sourceOrigin: Uri,
            reply: ReplyChannel,
        ) {
            try {
                havePendingRequest = false
                pendingRequestIsDoomed = false
                val result =
                    yubiKitFidoClient.makeCredential(sourceOrigin.toString(), message, null).fold(
                        onSuccess = {
                            it
                        },
                        onFailure = {
                            throw it
                        }
                    )

                logger.debug("webAuthnMakeCredential result: {}", result)

                val successArray = mutableListOf<Any>()
                successArray.add("success")
                successArray.add(JSONObject(result))
                successArray.add(CREATE_UNIQUE_KEY)
                reply.send(JSONArray(successArray).toString())
                replyChannel = null
            } catch (t: Throwable) {
                reportFailure("Error: ${t.message}", CREATE_UNIQUE_KEY)
            }
        }

        /** Invalidates any current request.  */
        fun onPageStarted() {
            if (havePendingRequest) {
                pendingRequestIsDoomed = true
            }
        }

        /** Sends an error result to the page.  */
        private fun reportFailure(message: String, type: String) {
            havePendingRequest = false
            pendingRequestIsDoomed = false
            val reply: ReplyChannel = replyChannel!! // verifies non null by throwing NPE
            replyChannel = null
            postErrorMessage(reply, message, type)
        }

        private fun postErrorMessage(reply: ReplyChannel, errorMessage: String, type: String) {
            logger.trace("Sending error message back to the page via replyChannel {}", errorMessage)
            val array = mutableListOf<Any?>()
            array.add("error")
            array.add(errorMessage)
            array.add(type)
            reply.send(JSONArray(array).toString())
            Toast.makeText(this.activity.applicationContext, errorMessage, Toast.LENGTH_SHORT)
                .show()
        }

        private class JavaScriptReplyChannel(private val reply: JavaScriptReplyProxy) :
            ReplyChannel {
            private val logger = LoggerFactory.getLogger(JavaScriptReplyChannel::class.java)
            override fun send(message: String?) {
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                    try {
                        reply.postMessage(message!!)
                    } catch (t: Throwable) {
                        logger.error("Reply failure due to: ", t)
                    }
                }
            }
        }

        /** ReplyChannel is the interface over which replies to the embedded site are sent. This allows
        for testing because AndroidX bans mocking its objects.*/
        interface ReplyChannel {
            fun send(message: String?)
        }

        companion object {
            const val CREATE_UNIQUE_KEY = "create"
            const val GET_UNIQUE_KEY = "get"
            const val TYPE_KEY = "type"
            const val REQUEST_KEY = "request"
        }

    }
}