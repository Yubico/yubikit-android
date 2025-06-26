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

package com.yubico.yubikit.android.app.ui.fido

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.app.databinding.FragmentFidoAppLocalBinding
import com.yubico.yubikit.core.internal.codec.Base64
import com.yubico.yubikit.fido.android.YubiKitFidoClient
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.random.Random

class FidoAppLocalFragment : Fragment() {
    private val logger = LoggerFactory.getLogger(FidoAppLocalFragment::class.java)
    private lateinit var binding: FragmentFidoAppLocalBinding
    private lateinit var yubiKitFidoClient: YubiKitFidoClient


    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        yubiKitFidoClient = YubiKitFidoClient(this)
        binding = FragmentFidoAppLocalBinding.inflate(inflater, container, false)
        return binding.root
    }

    private fun buildMcRequest(
        rpId: String,
        userName: String,
        rpName: String? = null,
        userDisplayName: String? = null
    ): String {
        val challenge = ByteArray(16).also { Random.Default.nextBytes(it) }
        val userId = ByteArray(32).also { Random.Default.nextBytes(it) }
        return """
                {
                    "challenge": "{CHALLENGE}",
                    "rp": {
                      "id": "{RP_ID}",
                      "name": "{RP_NAME}"
                    },
                    "user": {
                      "id": "{USER_RP_ID}",
                      "name": "{USER_NAME}",
                      "displayName": "{USER_DISPLAY_NAME}"
                    },
                    "attestation": "direct",
                    "authenticatorSelection": {
                      "userVerification": "required",
                      "residentKey": "required",
                      "requireResidentKey": true,
                      "authenticatorAttachment": "cross-platform"
                    },
                    "excludeCredentials": [],
                    "timeout": 90000,
                    "extensions": {
                      "credProps": true
                    },
                    "pubKeyCredParams": [
                      {
                        "alg": -8,
                        "type": "public-key"
                      },
                      {
                        "alg": -7,
                        "type": "public-key"
                      },
                      {
                        "alg": -257,
                        "type": "public-key"
                      }
                    ]
                  }                
            """
            .replace("{CHALLENGE}", Base64.toUrlSafeString(challenge))
            .replace("{RP_ID}", rpId)
            .replace("{RP_NAME}", rpName ?: rpId)
            .replace("{USER_ID}", Base64.toUrlSafeString(userId))
            .replace("{USER_NAME}", userName)
            .replace("{USER_DISPLAY_NAME}", userDisplayName ?: userName)
            .trimIndent()
    }

    private fun buildGaRequest(
        rpId: String
    ): String {
        val challenge = ByteArray(16).also { Random.Default.nextBytes(it) }
        return """
                {
                    "challenge": "{CHALLENGE}",
                    "rpId": "{RP_ID}",
                    "userVerification": "required",
                    "timeout": 90000,
                    "allowCredentials": []
                }
            """
            .replace("{CHALLENGE}", Base64.toUrlSafeString(challenge))
            .replace("{RP_ID}", rpId)
            .trimIndent()
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnMc.setOnClickListener {
            lifecycleScope.launch {
                val rpId = "demo.yubico.app"
                val mcRequest = buildMcRequest(
                    rpId,
                    "App test user"
                )

                yubiKitFidoClient.makeCredential(rpId, mcRequest).fold(
                    onSuccess = { result ->
                        logger.debug("Successful MC: {}", result)
                    },
                    onFailure = { error ->
                        logger.error("Error during MC: ${error.message}")
                    }
                )
            }
        }

        binding.btnGa.setOnClickListener {
            lifecycleScope.launch {
                val rpId = "demo.yubico.app"
                val gaRequest = buildGaRequest(
                    rpId,
                )

                yubiKitFidoClient.getAssertion(rpId, gaRequest).fold(
                    onSuccess = { result ->
                        logger.debug("Successful GA: {}", result)
                    },
                    onFailure = { error ->
                        logger.error("Error during GA: ${error.message}")
                    }
                )
            }
        }
    }
}