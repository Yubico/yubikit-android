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

package com.yubico.yubikit.demo.oath

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.*
import android.widget.Toast
import androidx.lifecycle.*
import androidx.lifecycle.Observer
import androidx.navigation.fragment.findNavController
import androidx.navigation.ui.onNavDestinationSelected
import androidx.recyclerview.widget.LinearLayoutManager
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.oath.qr.QrActivity
import com.yubico.yubikit.demo.settings.Ramps
import com.yubico.yubikit.oath.OathApplication
import com.yubico.yubikit.utils.Logger
import kotlinx.android.synthetic.main.fragment_oath.empty_list
import kotlinx.android.synthetic.main.fragment_oath.fab_button
import kotlinx.android.synthetic.main.fragment_oath.list
import kotlinx.android.synthetic.main.fragment_oath.swiperefresh

private const val REQUEST_SCAN_QR = 3
private const val TAG = "OathFragment"
class OathFragment : BaseYubikeyFragment(TAG), OnRecyclerViewItemClickListener, OperationsListDialogFragment.Listener, PasswordDialogFragment.DialogListener {

    // this view model can be per fragment because we're not sharing it's data with any other activity or fragment
    private val viewModel: OathViewModel by lazy {
        ViewModelProviders.of(this,
                OathViewModel.Factory(YubiKitManager(activity!!.applicationContext)))
                .get(OathViewModel::class.java)
    }
    private lateinit var listAdapter : CredentialListAdapter

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_oath, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.credentials.observe(viewLifecycleOwner, Observer {
            it?.run {
                empty_list.text = resources.getString(R.string.oath_no_authenticators)
                empty_list.visibility = if(it.isEmpty()) View.VISIBLE else View.GONE
                listAdapter.submitList(it.toList())
                hideAllSnackBars()
                activity?.invalidateOptionsMenu()
            }
        })

        viewModel.passwordSet.observe(viewLifecycleOwner, Observer {
            hideAllSnackBars()
            Toast.makeText(context, if (viewModel.requireAuthentication == true) "Password is set" else "Password removed", Toast.LENGTH_LONG).show()
        })

        listAdapter = CredentialListAdapter(this)
        with(list) {
            layoutManager = LinearLayoutManager(context)
            adapter = listAdapter
        }

        fab_button.setOnClickListener {
            startActivityForResult(Intent(activity, QrActivity::class.java), REQUEST_SCAN_QR)
        }

        swiperefresh.setOnRefreshListener {
            viewModel.refreshList()
            hideAllSnackBars()
            swiperefresh.isRefreshing = false
        }
        empty_list.visibility = View.VISIBLE
    }

    override fun onError(throwable: Throwable) {
        when (throwable) {
            is ApduException -> {
                Log.e(TAG, "Status code : ${Integer.toHexString(throwable.statusCode)} ")
                when {
                    throwable.statusCode == OathApplication.AUTHENTICATION_REQUIRED_ERROR.toInt() -> Toast.makeText(context, "Operation requires touch. Please try operation again and tap button on yubikey to confirm it.", Toast.LENGTH_LONG).show()
                    throwable.statusCode == OathApplication.NO_SUCH_OBJECT.toInt() -> Toast.makeText(context, "Key doesn't have this credential", Toast.LENGTH_LONG).show()
                    else -> Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
                }
            }
            is AuthRequiredException -> {
                // prompt for password
                PasswordDialogFragment.newInstance(validation = true, hasPassword = false).show(childFragmentManager, "password")
            }
            is ApduException -> {
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
        }
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        if (hasPermissions) {
            viewModel.executeDemoCommands()
        }
    }

    override fun onNfcSession() {
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == Activity.RESULT_OK && requestCode == REQUEST_SCAN_QR) {
            val uri = data?.data
            Logger.d(uri?.toString() ?: "No Uri")
            if (uri != null) {
                viewModel.addCredential(uri, Ramps.OATH_USE_TOUCH.getValue(context) == true)
            } else {
                Toast.makeText(context, "No Uri", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.oath_toolbar_menu, menu)
    }

    override fun onPrepareOptionsMenu(menu: Menu) {
        super.onPrepareOptionsMenu(menu)
        menu.findItem(R.id.action_password).isVisible = viewModel.requireAuthentication != null
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when(item.itemId) {
            R.id.action_password -> {
                PasswordDialogFragment.newInstance(false, viewModel.requireAuthentication == true).show(childFragmentManager, "password")
                return true
            }
            R.id.action_reset -> {
                viewModel.reset()
                return true
            }
        }
        return item.onNavDestinationSelected(findNavController()) || super.onOptionsItemSelected(item)
    }

    override fun onRecyclerViewItemClicked(position: Int) {
        OperationsListDialogFragment.newInstance(R.array.oath_credential_operations_logo, R.array.oath_credential_operations, position)
                .show(childFragmentManager, "operations")
    }

    override fun onOperationsClicked(oparationPosition: Int, itemPosition: Int) {
        val credentials = listAdapter.getItemData(itemPosition)
        when(oparationPosition) {
            0 -> {
                viewModel.refreshCredential(credentials.first)
            }
            1 -> {
                viewModel.removeCredential(credentials.first)
            }
            2 -> {
                context?.apply {
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    if (credentials.second != null) {
                        clipboard.setPrimaryClip(ClipData.newPlainText("OTP", credentials.second?.value))
                        Toast.makeText(this, R.string.copied, Toast.LENGTH_LONG).show()
                    } else{
                        Toast.makeText(this, R.string.not_copied, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    override fun onPasswordProvided(password: String, passwordType: PasswordDialogFragment.PasswordType) {
        viewModel.checkPassword(password)
    }

    override fun onPasswordChanged(password: String, newPassword: String, passwordType: PasswordDialogFragment.PasswordType) {
        viewModel.changePassword(password, newPassword)
    }

    override fun onCancel() {
        viewModel.clearTasks()
    }
}