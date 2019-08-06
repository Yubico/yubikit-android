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

package com.yubico.yubikit.demo.fido.signin

import android.webkit.CookieManager
import okhttp3.Cookie
import okhttp3.HttpUrl

/**
 * Storage for cookies uses {@link CookieManager}
 * allows to register listener on cookie invalidation
 */
object CookieStorage {

    private var listener: CookiesChangeListener? = null

    fun saveCookies(url: HttpUrl, cookies: MutableList<Cookie>) {
        var cookieManager = CookieManager.getInstance()
        for (cookie in cookies) {
            cookieManager.setCookie(url.toString(), cookie.toString())
        }
    }

    fun invalidateCookies(userRemoved: Boolean = false) {
        CookieManager.getInstance().removeAllCookies(null)
        listener?.onRemoved(userRemoved)
    }

    fun loadCookies(url: HttpUrl): List<Cookie> {
        val cookieManager = CookieManager.getInstance()
        val cookies = ArrayList<Cookie>()
        if (cookieManager.getCookie(url.toString()) != null) {
            val splitCookies = cookieManager.getCookie(url.toString()).split("[,;]".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            for (i in splitCookies.indices) {
                Cookie.parse(url, splitCookies[i].trim { it <= ' ' })?.run {
                    cookies.add(this)
                }
            }
        }
        return cookies;
    }

    fun hasCookies() : Boolean {
        return CookieManager.getInstance().hasCookies()
    }
    
    fun registerListener(listener: CookiesChangeListener) {
        CookieStorage.listener = listener;
    }

    fun unregisterListener() {
        listener = null;

    }

    interface CookiesChangeListener {
        fun onRemoved(userRemoved: Boolean)
    }

}