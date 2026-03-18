/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.android.ui.internal

import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Build
import android.os.Message
import android.view.KeyEvent
import android.webkit.ClientCertRequest
import android.webkit.HttpAuthHandler
import android.webkit.RenderProcessGoneDetail
import android.webkit.SafeBrowsingResponse
import android.webkit.SslErrorHandler
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.annotation.RequiresApi

internal open class FidoWebViewClient(
    private val delegate: WebViewClient,
) : WebViewClient() {

    override fun doUpdateVisitedHistory(
        view: WebView?,
        url: String?,
        isReload: Boolean,
    ) {
        delegate.doUpdateVisitedHistory(view, url, isReload)
    }

    override fun onFormResubmission(
        view: WebView?,
        dontResend: Message?,
        resend: Message?,
    ) {
        delegate.onFormResubmission(view, dontResend, resend)
    }

    override fun onLoadResource(view: WebView?, url: String?) {
        delegate.onLoadResource(view, url)
    }

    override fun onPageCommitVisible(view: WebView?, url: String?) {
        delegate.onPageCommitVisible(view, url)
    }

    override fun onPageStarted(
        view: WebView?,
        url: String?,
        favicon: Bitmap?,
    ) {
        delegate.onPageStarted(view, url, favicon)
    }

    override fun onReceivedClientCertRequest(
        view: WebView?,
        request: ClientCertRequest?,
    ) {
        delegate.onReceivedClientCertRequest(view, request)
    }

    override fun onReceivedError(
        view: WebView?,
        request: WebResourceRequest?,
        error: WebResourceError?,
    ) {
        delegate.onReceivedError(view, request, error)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun onReceivedError(
        view: WebView?,
        errorCode: Int,
        description: String?,
        failingUrl: String?,
    ) {
        delegate.onReceivedError(view, errorCode, description, failingUrl)
    }

    override fun onReceivedHttpAuthRequest(
        view: WebView?,
        handler: HttpAuthHandler?,
        host: String?,
        realm: String?,
    ) {
        delegate.onReceivedHttpAuthRequest(view, handler, host, realm)
    }

    override fun onReceivedHttpError(
        view: WebView?,
        request: WebResourceRequest?,
        errorResponse: WebResourceResponse?,
    ) {
        delegate.onReceivedHttpError(view, request, errorResponse)
    }

    override fun onReceivedLoginRequest(
        view: WebView?,
        realm: String?,
        account: String?,
        args: String?,
    ) {
        delegate.onReceivedLoginRequest(view, realm, account, args)
    }

    override fun onReceivedSslError(
        view: WebView?,
        handler: SslErrorHandler?,
        error: SslError?,
    ) {
        delegate.onReceivedSslError(view, handler, error)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onRenderProcessGone(
        view: WebView?,
        detail: RenderProcessGoneDetail?,
    ): Boolean {
        return delegate.onRenderProcessGone(view, detail)
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    override fun onSafeBrowsingHit(
        view: WebView?,
        request: WebResourceRequest?,
        threatType: Int,
        callback: SafeBrowsingResponse?,
    ) {
        delegate.onSafeBrowsingHit(view, request, threatType, callback)
    }

    override fun onScaleChanged(
        view: WebView?,
        oldScale: Float,
        newScale: Float,
    ) {
        delegate.onScaleChanged(view, oldScale, newScale)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun onTooManyRedirects(
        view: WebView?,
        cancelMsg: Message?,
        continueMsg: Message?,
    ) {
        delegate.onTooManyRedirects(view, cancelMsg, continueMsg)
    }

    override fun onUnhandledKeyEvent(view: WebView?, event: KeyEvent?) {
        delegate.onUnhandledKeyEvent(view, event)
    }

    override fun shouldInterceptRequest(
        view: WebView?,
        request: WebResourceRequest?,
    ): WebResourceResponse? {
        return delegate.shouldInterceptRequest(view, request)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun shouldInterceptRequest(
        view: WebView?,
        url: String?,
    ): WebResourceResponse? {
        return delegate.shouldInterceptRequest(view, url)
    }

    override fun shouldOverrideKeyEvent(
        view: WebView?,
        event: KeyEvent?,
    ): Boolean {
        return delegate.shouldOverrideKeyEvent(view, event)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun shouldOverrideUrlLoading(
        view: WebView?,
        request: WebResourceRequest?,
    ): Boolean {
        return delegate.shouldOverrideUrlLoading(view, request)
    }

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun shouldOverrideUrlLoading(
        view: WebView?,
        url: String?,
    ): Boolean {
        return delegate.shouldOverrideUrlLoading(view, url)
    }

    override fun onPageFinished(view: WebView?, url: String?) {
        delegate.onPageFinished(view, url)
    }
}
