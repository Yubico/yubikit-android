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

package com.yubico.yubikit.demo.fido.listview

import android.os.Bundle
import android.util.Log
import android.view.*
import androidx.recyclerview.widget.LinearLayoutManager
import android.widget.Toast
import androidx.lifecycle.Observer

import androidx.lifecycle.ViewModelProviders
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import androidx.navigation.ui.onNavDestinationSelected
import com.yubico.yubikit.demo.fido.R
import com.yubico.yubikit.demo.fido.arch.Injection
import com.yubico.yubikit.demo.fido.communication.ApiUtils
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import com.yubico.yubikit.demo.fido.settings.Ramps
import com.yubico.yubikit.demo.fido.signin.LoginViewModel
import com.yubico.yubikit.fido.AuthenticatorAttachment
import java.util.Locale
import java.lang.IllegalStateException
import kotlinx.android.synthetic.main.fragment_authenticator_list.*

/**
 * A fragment representing a list of Authenticators registered on web service.
 */
class AuthenticatorListFragment : UserDataFragment(), OperationsListDialogFragment.Listener, AddAuthenticatorDialogFragment.DialogListener, RenameDialogFragment.DialogListener {

    private lateinit var listAdapter : AuthenticatorListAdapter
    private lateinit var loginViewModel: LoginViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_authenticator_list, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Set the listAdapter
        listAdapter = AuthenticatorListAdapter(object : OnRecyclerViewItemClickListener {
            override fun onRecyclerViewItemClicked(position: Int) {
                OperationsListDialogFragment.newInstance(R.array.operations_logo, R.array.operations, position).show(childFragmentManager, "operations")
            }
        })
        with(list) {
            layoutManager = LinearLayoutManager(context)
            adapter = listAdapter
        }

        activity?.let {
            // this is shared view models, require passing activity (not fragment)
            loginViewModel = ViewModelProviders.of(it, LoginViewModel.Factory(
                    ApiUtils.getApiService(),
                    Injection.provideAccountStorage(view.context.applicationContext))).get(LoginViewModel::class.java)

        }

        loginViewModel.signedUser.observe(this, Observer {
            if (it == null) {
                findNavController().navigate(R.id.login_fragment,
                        null,
                        NavOptions.Builder().setPopUpTo(R.id.main_fragment,true).build())
            }
        })


        fab_button.setOnClickLister(object : ExpandableFAB.Listener {
            override fun onOperationsClicked(position: Int) {
                showProgress(true)
                viewModel.registerBegin(if(position == 1) AuthenticatorAttachment.CROSS_PLATFORM else AuthenticatorAttachment.PLATFORM)
            }
        })

        swiperefresh.setOnRefreshListener {
            viewModel.loadAuthenticators()
        }

        viewModel.networkRequestInProgress.observe(viewLifecycleOwner, Observer {
            showProgress(false)
        })

        viewModel.authenticators.observe(viewLifecycleOwner, Observer {
            listAdapter.submitList(it)
            empty_list.visibility = if(it.isEmpty()) View.VISIBLE else View.GONE
            empty_list.setText(R.string.no_authenticators)
            showProgress(false)

            val localDeviceId = accountStorage.getDeviceId()
            // we've got current platform authenticator, let's allow to add only cross-platform authenticators
            fab_button.makeExpandable(!it.map { item -> item.id }.contains(localDeviceId))
        })

        viewModel.authResultRequest.observe(viewLifecycleOwner, Observer {
            when(it) {
                is AuthenticatorModel.RequestResult.Success -> {
                    // operation was approved
                    viewModel.confirmOperation()
                }
                is AuthenticatorModel.RequestResult.Error -> {
                    // reject operation
                    Toast.makeText(context, "Error during authentication: ${it.error.message}", Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Network call failed: ${it.error.message}\"", it.error)
                    showProgress(false)
                }
            }
        })

        viewModel.loadAuthenticators()
        showProgress(true)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.list_toolbar_menu, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_logout) {
            loginViewModel.logout(userData)
            return true
        }
        return item.onNavDestinationSelected(findNavController()) || super.onOptionsItemSelected(item)
    }

    override fun onOperationsClicked(oparationPosition: Int, itemPosition: Int) {
        var authenticatorItem = listAdapter.getItemData(itemPosition)
        when(oparationPosition) {
            0 -> {
                showProgress(true)
                viewModel.delete(authenticatorItem, Ramps.PASSWORDLESS_EXPERIENCE.getValue(activity) == true)
            }
            1 -> RenameDialogFragment.newInstance(authenticatorItem.id, authenticatorItem.name).show(childFragmentManager, "rename")
            else -> throw IllegalStateException("Unknown operations")
        }
    }

    override fun onAddAuthenticator(authenticatorAttachment: AuthenticatorAttachment) {
        showProgress(true)
        viewModel.registerBegin(authenticatorAttachment)
    }

    override fun onAddCancel(authenticatorAttachment: AuthenticatorAttachment) {
        // if user doesn't add xplat authenticator log them out
        if (authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM) {
            loginViewModel.logout(userData)
        }
    }

    override fun onRename(itemid: String, newName: String) {
        showProgress(true)
        viewModel.rename(itemid, newName)
    }

    override fun handleError(e: Throwable) {

        showProgress(false)
        when (e) {
            is NoPlatformAuthenticatorException-> {
                fab_button.makeExpandable(true)
                if (BuildConfig.isWebAuthNNameSpace())
                    AddAuthenticatorDialogFragment.newInstance(userData, AuthenticatorAttachment.PLATFORM).show(childFragmentManager, "alert")
                else {
                    loginViewModel.logout(userData)
                }
            }
            is NoCrossPlatAuthenticatorException -> {
                showProgress(true)
                viewModel.registerBegin(AuthenticatorAttachment.CROSS_PLATFORM)
            }
            else -> {
                Toast.makeText(context, "Error occurred: ${e.message}", Toast.LENGTH_LONG).show()
                if (viewModel.authenticators.value == null) {
                    empty_list.visibility = View.VISIBLE
                    empty_list.text = String.format(Locale.ROOT, resources.getString(R.string.no_authenticators_error), e.message)
                } else if (Ramps.PASSWORDLESS_EXPERIENCE.getValue(context) == true && viewModel.authenticators.value?.none { item -> item.authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM } == true) {
                    // no cross-platform authenticator was added
                    AddAuthenticatorDialogFragment.newInstance(userData, AuthenticatorAttachment.CROSS_PLATFORM).show(childFragmentManager, "alert")
                }
            }
        }
    }

    private fun showProgress(refreshing: Boolean) {
        progress_bar.visibility = if (refreshing) View.VISIBLE else View.GONE
        swiperefresh.isRefreshing = false
    }

    companion object {
        const val TAG = "AuthenticatorFragment"
    }
}
