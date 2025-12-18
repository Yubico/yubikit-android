/*
 * Copyright (C) 2019-2022,2024 Yubico.
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

package com.yubico.yubikit.android.app.ui.piv

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.databinding.FragmentPivCertifiateBinding
import com.yubico.yubikit.android.app.ui.getSecret
import com.yubico.yubikit.core.keys.PrivateKeyValues
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec
import com.yubico.yubikit.piv.jca.PivProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("SpellCheckingInspection")
private const val DER_KEY =
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0G266KNssenUQ" +
        "wsqN3+f3ysmiHgp4345wsaiDcxXryXX3pXr3vYdiJFQ6HiiMbfdpm4FeulLYCOdB" +
        "ghKHIh/MnxTuwq6mPrxzLFxqGfHinvORc4Y+mZSiicN/Ajo+uQdgH5LrhlHJ0g7a" +
        "e26RWW3Z4pOel/SeXWJgKm4prhKzi6Or3NZ1l4Wpg4C/lrLD9/bhL6XdUmr/kXc2" +
        "UoldUz1ZyTNmDqr0oyix52jX+Tpxp7WsPUmXUoapxVpugOQKlkCGFltb5jnaK8VY" +
        "rlBfN0a7N0o+HCSIThjBLbr65qKXOmUYgS+q5OmidyeCz/1AJ5OLwSf63M71NXMt" +
        "ZoJjLdMBAgMBAAECggEAT6Z+HnfpDc+OK/5pQ7sMxCn7Z+WvLet3++ClrJRd0mvC" +
        "7uVQ73TzBXUZhqZFumz7aMnrua/e6UlutCrI9NgjhgOoZzrTsBO4lZq9t/KHZXh0" +
        "MRQM/2w+Lm+MdIPQrGJ5n4n3GI/LZdyu0vKZYFBTY3NvY0jCVrLnya2aEHa6MIpH" +
        "sDyJa0EpjZRMHscPAP4C9h0EE/kXdFuu8Q4I+RUhnWAEAox9wGq05cbWAnzz6f5W" +
        "WWHUL2CfPvSLHx7jjCXOmXf035pj91IfHghVoQyU0UW29xKSqfJv7nJwqV67C0cb" +
        "kd2MeNARiFi7z4kp6ziLU6gPeLQq3iyWy35hTYPl3QKBgQDdlznGc4YkeomH3W22" +
        "nHol3BUL96gOrBSZnziNM19hvKQLkRhyIlikQaS7RWlzKbKtDTFhPDixWhKEHDWZ" +
        "1DRs9th8LLZHXMP+oUyJPkFCX28syP7D4cpXNMbRk5yJXcuF72sYMs4dldjUQVa2" +
        "9DaEDkaVFOEAdIVOPNmvmE7MDwKBgQDQEyImwRkHzpp+IAFqhy06DJpmlnOlkD0A" +
        "hrDAT+EpXTwJssZK8DHcwMhEQbBt+3jXjIXLdko0bR9UUKIpviyF3TZg7IGlMCT4" +
        "XSs/UlWUct2n9QRrIV5ivRN5+tZZr4+mxbm5d7aa73oQuZl70d5mn6P4y5OsEc5s" +
        "XFNwUSCf7wKBgDo5NhES4bhMCj8My3sj+mRgQ5d1Z08ToAYNdAqF6RYBPwlbApVa" +
        "uPfP17ztLBv6ZNxbjxIBhNP02tCjqOHWhD/tTEy0YuC1WzpYn4egN/18nfWiim5l" +
        "sYjgcS04H/VoE8YJdpZRIx9a9DIxSNuhp4FjTuB1L/mypCQ+kOQ2nN25AoGBAJlw" +
        "0qlzkorQT9ucrI6rWq3JJ39piaTZRjMCIIvhHDENwT2BqXsPwCWDwOuc6Ydhf86s" +
        "oOnWtIgOxKC/yaYwyNJ6vCQjpMN1Sn4g7siGZffP8Sdvpy99bwYvWpKEaNfAgJXC" +
        "j+B2qKF+4iw9QjMuI+zX4uqQ7bhhdTExsJJOMVnfAoGABSbxwvLPglJ6cpoqyGL5" +
        "Ihg1LS4qog29HVmnX4o/HLXtTCO169yQP5lBWIGRO/yUcgouglJpeikcJSPJROWP" +
        "Ls4b2aPv5hhSx47MGZbVAIhSbls5zOZXDZm4wdfQE5J+4kAVlYF73ZCrH24Zbqqy" +
        "MF/0wDt/NExsv6FMUwSKfyY="

@Suppress("SpellCheckingInspection")
private const val PEM_CERT =
    "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSzCCAjOgAwIBAgIUG0ZaYHxZYLPZjCDgXsoGMOC5iUcwDQYJKoZIhvcNAQEL\n" +
        "BQAwNTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRAwDgYDVQQD\n" +
        "DAdFeGFtcGxlMB4XDTIwMDcyMDE4NDQ1MVoXDTIxMDcyMDE4NDQ1MVowNTEhMB8G\n" +
        "A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRAwDgYDVQQDDAdFeGFtcGxl\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBtuuijbLHp1EMLKjd/n\n" +
        "98rJoh4KeN+OcLGog3MV68l196V6972HYiRUOh4ojG33aZuBXrpS2AjnQYIShyIf\n" +
        "zJ8U7sKupj68cyxcahnx4p7zkXOGPpmUoonDfwI6PrkHYB+S64ZRydIO2ntukVlt\n" +
        "2eKTnpf0nl1iYCpuKa4Ss4ujq9zWdZeFqYOAv5ayw/f24S+l3VJq/5F3NlKJXVM9\n" +
        "WckzZg6q9KMosedo1/k6cae1rD1Jl1KGqcVaboDkCpZAhhZbW+Y52ivFWK5QXzdG\n" +
        "uzdKPhwkiE4YwS26+uailzplGIEvquTponcngs/9QCeTi8En+tzO9TVzLWaCYy3T\n" +
        "AQIDAQABo1MwUTAdBgNVHQ4EFgQU8WaODuaBCdcJSnl3eLwMP/LXB8AwHwYDVR0j\n" +
        "BBgwFoAU8WaODuaBCdcJSnl3eLwMP/LXB8AwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n" +
        "hkiG9w0BAQsFAAOCAQEAgdYSnE5oGKBFopMusBgXAtnruMSs9kUbgvdUyUhhtcuz\n" +
        "lrZWFbPB03/JHkj7iWYPNBEHX1R8NRJNvOSk5gl6f0P6A6545v2/qxQLsycQtBNi\n" +
        "5A0Tq/5FOLyfKndl/C4gGhWQDrGg+plcoIRDHCQufl4HEOVLQH0XC6UfUM8fWQGO\n" +
        "vRQCyUZyp47ZNjZTRTYoN+pgacXqDtVQa9GF+EZLEbEi2VZCuTboNW6kFNHpxjzV\n" +
        "3+6LWNPWuUYyku20L1w4AZtrzs3EE7eAEV6WVPypvhx7yTx6FonXVFEnj+tJ8Eqb\n" +
        "pt7FXTomDQnn8TStwUryxK3Wjv61pBVhfRb2BFU4og==\n" +
        "-----END CERTIFICATE-----\n"

class PivCertificateFragment : Fragment() {
    private val pivViewModel: PivViewModel by activityViewModels()

    private lateinit var binding: FragmentPivCertifiateBinding
    private lateinit var slot: Slot

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        binding = FragmentPivCertifiateBinding.inflate(inflater, container, false)
        return binding.root
    }

    @SuppressLint("SetTextI18n")
    override fun onViewCreated(
        view: View,
        savedInstanceState: Bundle?,
    ) {
        super.onViewCreated(view, savedInstanceState)
        slot = Slot.fromValue(requireArguments().getInt(ARG_SLOT))
        binding.title.text = getString(requireArguments().getInt(ARG_TITLE))
        showCerts(false)

        pivViewModel.certificates.observe(
            viewLifecycleOwner,
            Observer {
                it ?: return@Observer
                val cert = it.get(slot.value)
                showCerts(cert != null)
                if (cert != null) {
                    val expiration = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(cert.notAfter)
                    val keyType =
                        try {
                            KeyType.fromKey(cert.publicKey)
                        } catch (_: IllegalArgumentException) {
                            null
                        }
                    binding.certInfo.text = "Issuer: ${cert.issuerDN}\n" +
                        "Subject name: ${cert.subjectDN}\n" +
                        "Expiration date: $expiration\n" +
                        "Key type: ${keyType?.toString() ?: cert.publicKey.algorithm}"
                    binding.sign.isEnabled = (keyType != null && keyType != KeyType.X25519)
                }
            },
        )

        // Import a static key and self-signed certificate
        binding.importCert.setOnClickListener {
            val cert =
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(PEM_CERT.byteInputStream()) as X509Certificate
            val key =
                KeyFactory.getInstance("RSA")
                    .generatePrivate(PKCS8EncodedKeySpec(Base64.decode(DER_KEY, Base64.DEFAULT)))
            lifecycleScope.launch(Dispatchers.Main) {
                pivViewModel.pendingAction.value = {
                    authenticate(pivViewModel.mgmtKey)
                    putKey(slot, PrivateKeyValues.fromPrivateKey(key), PinPolicy.DEFAULT, TouchPolicy.DEFAULT)
                    putCertificate(slot, cert)
                    "Imported certificate ${cert.subjectDN} issued by ${cert.issuerDN}"
                }
            }
        }

        // Generate a key, then a self-signed certificate, and import
        binding.generateEcCert.setOnClickListener {
            lifecycleScope.launch(Dispatchers.Main) {
                generateKeyAndCert(slot, KeyType.ECCP256, "SHA256withECDSA")
            }
        }

        // Generate a key, then a self-signed certificate, and import
        binding.generateEd25519Cert.setOnClickListener {
            lifecycleScope.launch(Dispatchers.Main) {
                generateKeyAndCert(slot, KeyType.ED25519, "ED25519")
            }
        }

        binding.generateX25519Cert.setOnClickListener {
            lifecycleScope.launch(Dispatchers.Main) {
                generateKeyAndCert(slot, KeyType.X25519, "ED25519")
            }
        }

        binding.generateRsaCert.setOnClickListener {
            lifecycleScope.launch(Dispatchers.Main) {
                generateKeyAndCert(slot, KeyType.RSA2048, "SHA256withRSA")
            }
        }

        // Attest the certificate
        binding.attest.setOnClickListener {
            pivViewModel.pendingAction.value = {
                val cert = attestKey(slot)
                "Received certificate ${cert.subjectDN} issued by ${cert.issuerDN}"
            }
        }

        // Delete the certificate
        binding.delete.setOnClickListener {
            pivViewModel.pendingAction.value = {
                authenticate(pivViewModel.mgmtKey)
                deleteCertificate(slot)
                "Deleted certificate in slot $slot"
            }
        }

        // Sign a message using the key, verify the signature using the certificate
        binding.sign.setOnClickListener {
            val messageBytes = binding.message.text.toString().toByteArray()
            lifecycleScope.launch(Dispatchers.Main) {
                getSecret(requireContext(), R.string.enter_pin)?.let { pin ->
                    pivViewModel.pendingAction.value = {
                        val provider = PivProvider(this)

                        val keyStore = KeyStore.getInstance("YKPiv", provider)
                        keyStore.load(null)
                        val publicKey = keyStore.getCertificate(slot.stringAlias).publicKey
                        val privateKey = keyStore.getKey(slot.stringAlias, pin.toCharArray()) as PrivateKey

                        val keyType = KeyType.fromKey(publicKey)
                        val algorithm =
                            when (keyType.params.algorithm) {
                                KeyType.Algorithm.RSA -> "SHA256withRSA"
                                KeyType.Algorithm.EC -> if (keyType == KeyType.ED25519) "Ed25519" else "SHA256withECDSA"
                            }

                        // Create signature
                        val signature =
                            Signature.getInstance(algorithm, provider).apply {
                                initSign(privateKey)
                                update(messageBytes)
                            }.sign()

                        // Verify signature
                        val result =
                            Signature.getInstance(algorithm).apply {
                                initVerify(publicKey)
                                update(messageBytes)
                            }.verify(signature)

                        if (result) {
                            "Signature verified: ${Base64.encodeToString(signature, Base64.DEFAULT)}"
                        } else {
                            "Signature verification failed"
                        }
                    }
                }
            }
        }
    }

    private fun showCerts(visible: Boolean) {
        binding.certInfo.visibility = if (visible) View.VISIBLE else View.INVISIBLE
        binding.noCert.visibility = if (visible) View.INVISIBLE else View.VISIBLE

        binding.delete.isEnabled = visible
        binding.sign.isEnabled = visible
    }

    private fun keyPairGen(keyType: KeyType): String =
        when (keyType) {
            KeyType.ECCP256, KeyType.ECCP384, KeyType.ED25519, KeyType.X25519 -> "YKPivEC"
            else -> "YkPivRSA"
        }

    private suspend fun generateKeyAndCert(
        slot: Slot,
        keyType: KeyType,
        signatureAlgorithm: String,
    ) {
        getSecret(requireContext(), R.string.enter_pin)?.let { pin ->
            pivViewModel.pendingAction.value = {
                authenticate(pivViewModel.mgmtKey)

                val provider = PivProvider(this)
                val factory = KeyPairGenerator.getInstance(keyPairGen(keyType), provider)
                factory.initialize(
                    PivAlgorithmParameterSpec(
                        slot,
                        keyType,
                        PinPolicy.DEFAULT,
                        TouchPolicy.DEFAULT,
                        pin.toCharArray(),
                    ),
                )
                val keyPair = factory.generateKeyPair()

                // Generate a certificate
                val name = X500Name("CN=Generated ${keyType.name} Example")
                val serverCertGen =
                    X509v3CertificateBuilder(
                        name,
                        BigInteger("123456789"),
                        Date(),
                        Date(),
                        name,
                        SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.public.encoded)),
                    )

                val signer =
                    if (keyType == KeyType.X25519) {
                        val kpg = KeyPairGenerator.getInstance(signatureAlgorithm)
                        kpg.initialize(255)

                        JcaContentSignerBuilder(signatureAlgorithm).build(kpg.generateKeyPair().private)
                    } else {
                        CertContentSigner(
                            provider,
                            keyPair.private,
                            signatureAlgorithm,
                        )
                    }

                val cert =
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(
                            ByteArrayInputStream(serverCertGen.build(signer).encoded),
                        ) as X509Certificate
                putCertificate(slot, cert)

                "Generated ${keyType.name} key in slot $slot"
            }
        }
    }

    private class CertContentSigner(
        private val provider: PivProvider,
        private val privateKey: PrivateKey,
        private val signatureAlgorithm: String,
    ) : ContentSigner {
        val messageBuffer = ByteArrayOutputStream()

        override fun getAlgorithmIdentifier() = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

        override fun getOutputStream(): OutputStream = messageBuffer

        override fun getSignature(): ByteArray {
            return Signature.getInstance(signatureAlgorithm, provider).apply {
                initSign(privateKey)
                update(messageBuffer.toByteArray())
            }.sign()
        }
    }

    companion object {
        private const val ARG_SLOT = "slot"
        private const val ARG_TITLE = "title"

        @JvmStatic
        fun newInstance(
            slot: Slot,
            title: Int,
        ) = PivCertificateFragment().apply {
            arguments =
                Bundle().apply {
                    putInt(ARG_SLOT, slot.value)
                    putInt(ARG_TITLE, title)
                }
        }
    }
}
