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

package com.yubico.yubikit.demo.fido.signin

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.yubico.yubikit.demo.fido.R
import com.yubico.yubikit.demo.fido.network.ResourceNotFoundException
import kotlinx.android.synthetic.main.fragment_suggested_accounts.sign_in_button
import kotlinx.android.synthetic.main.fragment_suggested_accounts.username

/**
 * Dialog that shows all passwordless accounts that application aware of
 */
class SuggestedAccountsFragment : BaseLoginFragment() {

    private val navOptions =  NavOptions.Builder().setPopUpTo(R.id.suggested_accounts_fragment, true).build()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_suggested_accounts, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        sign_in_button.setOnClickListener {
            findNavController().navigate(R.id.login_fragment, LoginFragment.getArguments(false))
        }

        val prevAccount = viewModel.passwordlessAccount
        if (prevAccount == null) {
            // account was removed / not passwordless anymore - back to generic sign in page and remove this fragment from fragment backstack
            findNavController().navigate(R.id.login_fragment, null, navOptions)
        } else {
            username.text = prevAccount.username
            username.setOnClickListener {
                // start passwordless authentication
                context?.let {
                    showProgress(true)
                    viewModel.authenticateBegin(prevAccount, true)
                }
            }
        }
    }

    override fun getLoginForm() = R.id.login_form
    override fun getLoginProgress() = R.id.login_progress
    override fun getFragmentId() = R.id.suggested_accounts_fragment

    override fun handleError(error: Throwable?) {
        error?.run {
            Toast.makeText(context, error.message, Toast.LENGTH_LONG).show()
            if (error is ResourceNotFoundException) {
                // account was removed / not passwordless anymore - back to generic sign in page and remove this fragment from fragment backstack
                findNavController().navigate(R.id.login_fragment, null, navOptions)
            }
        }
    }
}