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

package com.yubico.yubikit.demo
import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import com.yubico.yubikit.demo.fido.settings.IBuildConfig
import com.yubico.yubikit.demo.fido.settings.Ramps
import com.yubico.yubikit.demo.fido.signin.CookieStorage

class DemoApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)

        if (Ramps.EXPIRE_SESSION_ON_APP_START.getValue(this) == true) {
            // nuke all cookies at application launch, so that user has to authorize
            CookieStorage.invalidateCookies()
        }

        BuildConfig.setConfig(object : IBuildConfig {
            override fun getServerUrl(): String {
                return com.yubico.yubikit.demo.BuildConfig.SERVER_URL
            }

            override fun getNamespace(): String {
                return com.yubico.yubikit.demo.BuildConfig.NAMESPACE
            }

            override fun getAppName(): String {
                return com.yubico.yubikit.demo.BuildConfig.APP_NAME
            }

            override fun getVersion(): String {
                return com.yubico.yubikit.demo.BuildConfig.VERSION_NAME
            }
        })

    }
}