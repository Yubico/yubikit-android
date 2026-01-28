/*
 * Copyright (C) 2025-2026 Yubico.
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
import com.yubico.yubikit.fido.android.FidoClient
import com.yubico.yubikit.fido.android.Origin
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import kotlin.random.Random

class FidoAppLocalFragment : Fragment() {
    private val logger = LoggerFactory.getLogger(FidoAppLocalFragment::class.java)
    private var _binding: FragmentFidoAppLocalBinding? = null
    val binding get() = _binding!!
    private lateinit var fidoClient: FidoClient

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        fidoClient = FidoClient(this)
        _binding = FragmentFidoAppLocalBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun buildMcRequest(
        userName: String,
        userDisplayName: String = userName,
    ): String {
        val challenge = ByteArray(16).also { Random.nextBytes(it) }
        val userId = ByteArray(32).also { Random.nextBytes(it) }
        val request =
            McRequest(
                challenge = Base64.toUrlSafeString(challenge),
                rp = Rp(RP_ID, RP_ID),
                user = User(Base64.toUrlSafeString(userId), userName, userDisplayName),
            )

        return json.encodeToString(request)
    }

    private fun buildGaRequest(): String {
        val challenge = ByteArray(16).also { Random.nextBytes(it) }
        val request =
            GaRequest(
                challenge = Base64.toUrlSafeString(challenge),
                rpId = RP_ID,
            )
        return json.encodeToString(request)
    }

    override fun onViewCreated(
        view: View,
        savedInstanceState: Bundle?,
    ) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnMc.setOnClickListener {
            lifecycleScope.launch {
                val request = buildMcRequest("App test user")
                logger.debug("Make credential request: {}", request)

                fidoClient.makeCredential(Origin(ORIGIN), request, null)
                    .onSuccess { logger.debug("Successful MC: {}", it) }
                    .onFailure { logger.error("Error during MC: ", it) }
            }
        }

        binding.btnGa.setOnClickListener {
            lifecycleScope.launch {
                val request = buildGaRequest()
                logger.debug("Get assertions request: {}", request)

                fidoClient.getAssertion(Origin(ORIGIN), request, null)
                    .onSuccess { logger.debug("Successful GA: {}", it) }
                    .onFailure { logger.error("Error during GA:", it) }
            }
        }
    }

    companion object {
        const val ORIGIN = "https://demo.yubico.app"
        const val RP_ID = "demo.yubico.app"
        val json = Json { encodeDefaults = true }
    }
}
