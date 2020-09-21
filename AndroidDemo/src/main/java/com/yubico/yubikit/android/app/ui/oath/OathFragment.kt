package com.yubico.yubikit.android.app.ui.oath

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.android.app.ui.getSecret
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.oath.CredentialData
import com.yubico.yubikit.oath.HashAlgorithm
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.oath.OathType
import com.yubico.yubikit.core.util.RandomUtils
import com.yubico.yubikit.core.smartcard.SW
import kotlinx.android.synthetic.main.fragment_oath.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.apache.commons.codec.binary.Base32

class OathFragment : YubiKeyFragment<OathSession, OathViewModel>() {
    override val viewModel: OathViewModel by activityViewModels()

    lateinit var listAdapter: OathListAdapter

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_oath, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        listAdapter = OathListAdapter(object : OathListAdapter.ItemListener {
            override fun onDelete(credentialId: ByteArray) {
                lifecycleScope.launch(Dispatchers.Main) {
                    AlertDialog.Builder(requireContext())
                            .setTitle("Delete credential?")
                            .setPositiveButton("Delete") { _, _ ->
                                viewModel.pendingAction.value = {
                                    deleteCredential(credentialId)
                                    "Credential deleted"
                                }
                            }.setNegativeButton(android.R.string.cancel) { dialog, _ ->
                                dialog.cancel()
                            }.show()
                }
            }
        })
        with(credential_list) {
            layoutManager = LinearLayoutManager(context)
            adapter = listAdapter
        }

        swiperefresh.setOnRefreshListener {
            viewModel.pendingAction.value = { null }  // NOOP: Force credential refresh
            swiperefresh.isRefreshing = false
        }

        viewModel.result.observe(viewLifecycleOwner, Observer { result ->
            result.onFailure { e ->
                if (e is ApduException && e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED) {
                    viewModel.oathInfo.value?.deviceId?.let { deviceId ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            getSecret(requireContext(), R.string.enter_password, R.string.password)?.let {
                                viewModel.password = Pair(deviceId, it.toCharArray())
                            }
                        }
                    }
                }
            }
        })

        viewModel.credentials.observe(viewLifecycleOwner, Observer {
            listAdapter.submitList(it?.toList())
            empty_view.visibility = if (it == null) View.VISIBLE else View.GONE
        })

        text_layout_key.setEndIconOnClickListener {
            edit_text_key.setText(Base32().encodeToString(RandomUtils.getRandomBytes(10)))
        }
        edit_text_key.setText(Base32().encodeToString(RandomUtils.getRandomBytes(10)))

        btn_save.setOnClickListener {
            try {
                val secret = Base32().decode(edit_text_key.text.toString())
                val issuer = edit_text_issuer.text.toString()
                if (issuer.isBlank()) {
                    edit_text_issuer.error = "Issuer must not be empty"
                } else {
                    viewModel.pendingAction.value = {
                        putCredential(CredentialData("user@example.com", OathType.TOTP, HashAlgorithm.SHA1, secret, 6, 30, 0, issuer), false)
                        "Credential added"
                    }
                }
            } catch (e: Exception) {
                viewModel.postResult(Result.failure(e))
            }
        }
    }
}