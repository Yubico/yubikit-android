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

package com.yubico.yubikit.demo.piv

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.piv.Algorithm
import com.yubico.yubikit.piv.Slot
import kotlinx.android.synthetic.main.fragment_piv_certifiate.*
import java.text.SimpleDateFormat
import java.util.*
import javax.security.cert.X509Certificate
import android.content.Context
import android.widget.Toast
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.utils.StringUtils
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import javax.security.cert.CertificateException


class PivCertificateFragment : Fragment() {
    private lateinit var viewModel: PivViewModel
    private lateinit var slot: Slot

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_piv_certifiate, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        slot = Slot.fromValue(arguments!!.getInt(ARG_SLOT))
        title.text = getString(arguments!!.getInt(ARG_TITLE))
        showCerts(false)

        // this view shared between fragments
        viewModel = ViewModelProviders.of(activity!!,
                PivViewModel.Factory(YubiKitManager(view.context.applicationContext)))
                .get(PivViewModel::class.java)

        viewModel.certificates.observe(viewLifecycleOwner, Observer {
            it?:return@Observer
            val cert = it.get(slot.value)
            showCerts(cert != null)
            if (cert != null) {
                val expiration = SimpleDateFormat("yyyy-mm-dd", Locale.getDefault()).format(cert.notAfter)
                cert_info.text = "Issuer: ${cert.issuerDN}\nSubject name: ${cert.subjectDN}\nExpiration date:$expiration"
            }
        })

        generateKey.setOnClickListener {
            viewModel.generateKey(slot, Algorithm.values()[algorithm.selectedItemPosition])
        }
        importKey.setOnClickListener {
            viewModel.importKey(slot, generateKeyOnAndroid(Algorithm.values()[algorithm.selectedItemPosition]))
        }
        attest.setOnClickListener {
            viewModel.attest(slot)
        }
        sign.setOnClickListener {
            viewModel.sign(slot, Algorithm.values()[algorithm.selectedItemPosition], message.editableText.toString())
        }

        importCert.setOnClickListener {
            try {
                viewModel.importCertificate(slot, findFileImport(it.context))
            } catch (e: IOException) {
                Toast.makeText(context, e.message, Toast.LENGTH_LONG).show()
            }
        }
        export.setOnClickListener {
            try {
                viewModel.exportCertificate(slot, createFileExport(it.context))
            } catch (e: IOException) {
                Toast.makeText(context, e.message, Toast.LENGTH_LONG).show()
            }
        }

        delete.setOnClickListener {
            viewModel.deleteCertificate(slot)
        }
    }

    private fun showCerts(visible: Boolean) {
        cert_info.visibility = if (visible) View.VISIBLE else View.GONE
        no_cert.visibility = if (visible) View.GONE else View.VISIBLE

        delete.isEnabled = visible
        export.isEnabled = visible
    }

    private fun createFileExport(context: Context) : String {
        val file = File(context.filesDir, CERT_FILE_NAME_EXPORT)
        if (file.exists()) {
            file.delete()
        }
        file.createNewFile()
        return file.absolutePath
    }

    private fun findFileImport(context: Context) : String {
        val file = File(context.filesDir, CERT_FILE_NAME_EXPORT)
        var cert: X509Certificate? = null
        if (file.exists()) {
            // if we exported some cert we use it as default for import (if nothing was ever exported using default cert from asset)
            try {
                cert = X509Certificate.getInstance(file.readBytes())
            } catch (e: CertificateException) {
            }
        }
        if (cert == null) {
            // if nothing was exported within this session use cert from assets for demo purposes
            try {
                cert = X509Certificate.getInstance(context.assets.open("sampleCert.crt"))
            } catch (e: CertificateException) {
            }
        }

        val fileImport = File(context.filesDir, CERT_FILE_NAME_IMPORT)
        if (cert != null) {
            fileImport.writeBytes(cert.encoded)
        }
        return fileImport.absolutePath
    }

    private fun generateKeyOnAndroid(algorithm: Algorithm) : PrivateKey {
        val keygen =
        when(algorithm) {
            Algorithm.RSA1024 -> {
                KeyPairGenerator.getInstance("RSA").apply {
                    initialize(1024)
                }
            }
            Algorithm.RSA2048 -> {
                KeyPairGenerator.getInstance("RSA").apply {
                    initialize(2048)
                }
            }
            Algorithm.ECCP256 -> {
                KeyPairGenerator.getInstance("EC").apply {
                    initialize(ECGenParameterSpec("secp256r1"))
                }
            }
            else -> {
                KeyPairGenerator.getInstance("EC").apply {
                    initialize(ECGenParameterSpec("secp384r1"))
                }
            }
        }

        val keyPair = keygen.generateKeyPair()
        Toast.makeText(context, "Generated key ${algorithm.name} pair with public key: ${StringUtils.convertBytesToString(keyPair.public.encoded)}", Toast.LENGTH_SHORT).show()
        return keyPair.private
    }


    companion object {
        private const val ARG_SLOT = "slot"
        private const val ARG_TITLE = "title"
        private const val CERT_FILE_NAME_EXPORT = "CertExport.crt"
        private const val CERT_FILE_NAME_IMPORT = "CertImport.crt"

        @JvmStatic
        fun newInstance(slot: Slot, title: Int) = PivCertificateFragment().apply {
            arguments = Bundle().apply {
                putInt(ARG_SLOT, slot.value)
                putInt(ARG_TITLE, title)
            }
        }

    }
}