/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.webview

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.net.Uri
import android.net.http.SslError
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.*
import android.widget.Toast
import androidx.browser.customtabs.*
import androidx.fragment.app.Fragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import com.yubico.yubikit.demo.settings.Ramps
import kotlinx.android.synthetic.main.fragment_webview.*

private const val TAG = "WebViewFragment"
class WebViewFragment : Fragment() {

    private var customTabsClient: CustomTabsClient? = null
    private val uri = Uri.parse(BuildConfig.getServerUrl()).buildUpon().appendPath("webauthn").build()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_webview, container, false)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val context = view.context
        if (Ramps.USE_CUSTOM_TABS.getValue(context) == true) {
            webview.visibility = View.GONE
            launchCustomTabs(context, uri)
        } else {
            webview.visibility = View.VISIBLE
            webview.loadUrl(uri.toString())
            webview.settings.javaScriptEnabled = true
            webview.webViewClient = WebViewHandler()
        }

        refresh.setOnClickListener {
            launchCustomTabs(context, uri)
        }
    }

    private fun launchCustomTabs(context: Context, uri: Uri) {
        val packageName = CustomTabsClient.getPackageName(context, null) ?: "com.android.chrome"
        CustomTabsClient.bindCustomTabsService(context, packageName, object : CustomTabsServiceConnection() {
            override fun onCustomTabsServiceConnected(name: ComponentName?, client: CustomTabsClient?) {
                Log.d(TAG, "onCustomTabsServiceConnected $packageName")
                customTabsClient = client
                customTabsClient?.warmup(0)

                val session = customTabsClient?.newSession(object: CustomTabsCallback() {
                    override fun onNavigationEvent(navigationEvent: Int, extras: Bundle?) {
                        super.onNavigationEvent(navigationEvent, extras)
                        Log.d(TAG, "onNavigationEvent: Code = $navigationEvent")
                    }
                })
                session?.mayLaunchUrl(uri, null, null)
                val customtabs = CustomTabsIntent.Builder(session).build()
                customtabs.launchUrl(context, uri)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                Log.d(TAG, "onServiceDisconnected")
                customTabsClient = null
            }
        })
    }

    private class WebViewHandler : WebViewClient() {
        override fun onPageFinished(view: WebView?, url: String?) {
            super.onPageFinished(view, url)
            Log.d(TAG, url ?: "Empty URL")
        }

        override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
            super.onReceivedError(view, request, error)
            Log.e(TAG, error.toString())
            Toast.makeText(view?.context, error.toString(), Toast.LENGTH_LONG).show()
        }

        override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
            super.onReceivedSslError(view, handler, error)
            Log.e(TAG, error.toString())
            Toast.makeText(view?.context, error.toString(), Toast.LENGTH_LONG).show()
        }
    }
}