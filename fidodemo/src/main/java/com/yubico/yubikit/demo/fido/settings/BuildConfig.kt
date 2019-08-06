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

package com.yubico.yubikit.demo.fido.settings

object BuildConfig : IBuildConfig {
    const val TABLE_NAME = "authenticators"
    const val WEBAUTHN_NAMESPACE = "webauthnflow"

    private var config : IBuildConfig = object : IBuildConfig {
        override fun getServerUrl() : String {
            return "https://demo.yubico.com"
        }

        override fun getNamespace(): String {
            return WEBAUTHN_NAMESPACE
        }

        override fun getAppName(): String {
            return "YubikitDemo"
        }

        override fun getVersion(): String {
            return "1.0.0"
        }
    }

    fun setConfig (config : IBuildConfig) {
        BuildConfig.config = config
    }

    override fun getNamespace(): String {
        return config.getNamespace()
    }

    override fun getServerUrl(): String {
        return config.getServerUrl()
    }

    override fun getAppName(): String {
        return config.getAppName()
    }

    override fun getVersion(): String {
        return config.getVersion()
    }

    fun isWebAuthNNameSpace() : Boolean {
        return WEBAUTHN_NAMESPACE == getNamespace()
    }
}