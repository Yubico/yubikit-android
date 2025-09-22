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

package com.yubico.yubikit.fido.android.provider_service

import android.app.PendingIntent
import android.content.Intent
import android.content.res.Resources
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.ClearCredentialUnsupportedException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONObject
import org.slf4j.LoggerFactory

class YubiKitProviderService : CredentialProviderService() {

    private val logger = LoggerFactory.getLogger(YubiKitProviderService::class.java)

    /**
     * Called by the Android System in response to a client app calling
     * [androidx.credentials.CredentialManager.createCredential], to create/save a credential with
     * a credential provider installed on the device.
     */
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        logger.debug("onBeginCreateCredentialRequest.type: {}", request.type)
        logger.debug("callingAppInfo packageName: {}", request.callingAppInfo?.packageName)
        logger.debug(
            "callingAppInfo isOriginPopulated: {}",
            request.callingAppInfo?.isOriginPopulated()
        )
        logger.debug("callingAppInfo origin: {}", request.callingAppInfo?.getOrigin(allowList))
        logger.debug(
            "onBeginCreateCredentialRequest.candidateQueryData: {}",
            request.candidateQueryData
        )

        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("Unsupported credential request type: ${request.type}"))
            return
        }

        val requestJson = JSONObject(request.requestJson)
        val displayName = requestJson.optJSONObject("user")?.optString("displayName")

        if (displayName.isNullOrEmpty()) {
            callback.onError(CreateCredentialUnknownException("Missing user displayName"))
            return
        }

        val pe = PendingIntent.getActivity(
            applicationContext,
            REQUEST_CODE,
            Intent(applicationContext, YubiKitFido2ProviderActivity::class.java),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val response =
            BeginCreateCredentialResponse(listOf(CreateEntry.Builder(displayName, pe).build()))

        logger.debug("Sending BeginCreateCredentialResponse")
        callback.onResult(response)
    }

    /**
     * Called by the Android System in response to a client app calling
     * [androidx.credentials.CredentialManager.getCredential], to get a credential sourced from a
     * credential provider installed on the device.
     */
    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        logger.debug("onBeginGetCredentialRequest: {}", request.beginGetCredentialOptions)

        if (request.beginGetCredentialOptions.isEmpty()) {
            callback.onError(GetCredentialUnsupportedException("No credential options provided"))
            return
        }

        val credentialEntries: MutableList<CredentialEntry> = mutableListOf()
        var foundSupportedOption = false

        for (option in request.beginGetCredentialOptions) {

            if (option is BeginGetPublicKeyCredentialOption) {
                foundSupportedOption = true
                logger.trace("id  :               {}", option.id)
                logger.trace("type:               {}", option.type)
                logger.trace("requestJson:        {}", option.requestJson)
                logger.trace("clientDataHash:     {}", option.clientDataHash)
                logger.trace("candidateQueryData: {}", option.candidateQueryData)

                val pendingIntent = PendingIntent.getActivity(
                    applicationContext,
                    REQUEST_CODE,
                    Intent(applicationContext, YubiKitFido2ProviderActivity::class.java),
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )

                val icon = try {
                    Icon.createWithResource(applicationContext, R.drawable.ic_service)
                } catch (e: Resources.NotFoundException) {
                    logger.error("Resource not found: ic_service", e)
                    Icon.createWithResource(applicationContext, android.R.drawable.ic_dialog_alert)
                }

                val label = try {
                    applicationContext.getString(R.string.get_credential)
                } catch (e: Resources.NotFoundException) {
                    logger.error("Resource not found: get_credential", e)
                    "Credential" // Fallback label
                }

                val entry = PublicKeyCredentialEntry.Builder(
                    applicationContext,
                    label,
                    pendingIntent,
                    option
                )
                    // can use also .setDisplayName("Choose later...")
                    .setIcon(icon)
                    .setAutoSelectAllowed(false)
                    .build()

                credentialEntries.add(entry)
            }
        }

        if (!foundSupportedOption) {
            callback.onError(GetCredentialUnsupportedException("No supported credential options found"))
            return
        }

        val response = BeginGetCredentialResponse(credentialEntries)
        logger.debug("Sending BeginGetCredentialRequest")
        callback.onResult(response)
    }

    /**
     * Called by the Android System in response to a client app calling
     * [androidx.credentials.CredentialManager.getCredential], to get a credential sourced from a
     * credential provider installed on the device.
     */
    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        logger.debug("onClearCredentialStateRequest")
        callback.onError(ClearCredentialUnsupportedException("Not implemented"))
    }

    companion object {
        private const val REQUEST_CODE = 1
        val allowList = """
            {
              "apps": [
                {
                  "type": "android",
                  "info": {
                    "package_name": "com.android.chrome",
                    "signatures": [
                      {
                        "build": "release",
                        "cert_fingerprint_sha256": "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83"
                      },
                      {
                        "build": "release",
                        "cert_fingerprint_sha256": "5F:23:91:27:7B:1D:BD:48:90:00:46:7E:4C:2F:A6:AF:80:24:30:08:04:57:DC:E2:F6:18:99:2E:9D:FB:54:02"
                      }
                    ]
                  }
                },
                {
                  "type": "android",
                  "info": {
                    "package_name": "org.mozilla.firefox",
                    "signatures": [
                      {
                        "build": "release",
                        "cert_fingerprint_sha256": "A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04"
                      }
                    ]
                  }
                },
                {
                  "type": "android",
                  "info": {
                    "package_name": "com.google.android.gms",
                    "signatures": [
                      {
                        "build": "release",
                        "cert_fingerprint_sha256": "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83"
                      },
                      {
                        "build": "release",
                        "cert_fingerprint_sha256": "5F:23:91:27:7B:1D:BD:48:90:00:46:7E:4C:2F:A6:AF:80:24:30:08:04:57:DC:E2:F6:18:99:2E:9D:FB:54:02"
                      }
                    ]
                  }
                }
              ]
            }""".trimIndent()

    }
}