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
import com.yubico.yubikit.android.app.databinding.FragmentOathBinding
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.android.app.ui.getSecret
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SW
import com.yubico.yubikit.core.util.RandomUtils
import com.yubico.yubikit.oath.CredentialData
import com.yubico.yubikit.oath.HashAlgorithm
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.oath.OathType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.apache.commons.codec.binary.Base32

class OathFragment : YubiKeyFragment<OathSession, OathViewModel>() {
    override val viewModel: OathViewModel by activityViewModels()

    lateinit var binding: FragmentOathBinding
    lateinit var listAdapter: OathListAdapter

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        binding = FragmentOathBinding.inflate(inflater, container, false)
        return binding.root
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
        with(binding.credentialList) {
            layoutManager = LinearLayoutManager(context)
            adapter = listAdapter
        }

        binding.swiperefresh.setOnRefreshListener {
            viewModel.pendingAction.value = { null }  // NOOP: Force credential refresh
            binding.swiperefresh.isRefreshing = false
        }

        viewModel.result.observe(viewLifecycleOwner, Observer { result ->
            result.onFailure { e ->
                if (e is ApduException && e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED) {
                    viewModel.oathDeviceId.value?.let { deviceId ->
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
            binding.emptyView.visibility = if (it == null) View.VISIBLE else View.GONE
        })

        binding.textLayoutKey.setEndIconOnClickListener {
            binding.editTextKey.setText(Base32().encodeToString(RandomUtils.getRandomBytes(10)))
        }
        binding.editTextKey.setText(Base32().encodeToString(RandomUtils.getRandomBytes(10)))

        binding.btnSave.setOnClickListener {
            try {
                val secret = Base32().decode(binding.editTextKey.text.toString())
                val issuer = binding.editTextIssuer.text.toString()
                if (issuer.isBlank()) {
                    binding.editTextIssuer.error = "Issuer must not be empty"
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