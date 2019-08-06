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
import android.text.TextUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.ArrayAdapter
import android.widget.TextView
import android.widget.Toast
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.yubico.yubikit.demo.fido.R
import com.yubico.yubikit.demo.fido.settings.Ramps
import kotlinx.android.synthetic.main.fragment_login.*

/**
 * Fragment that represents sign in/sign up screen
 */
open class LoginFragment : BaseLoginFragment(){

    private val STATE_SIGNUP = "isSignUp"

    // one fragment is used for sign in and sign up screen
    private var isSignUp = false

    // whether to show user suggested password less account or not
    private var showSuggested = true

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_login, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        savedInstanceState?.let {
            isSignUp = it.getBoolean(STATE_SIGNUP, false)
        }

        arguments?.let {
            showSuggested = it.getInt(ARG_SHOW_SUGGESTED) == 1
        }

        sign_in_button.setOnClickListener { attemptLogin() }
        // Set up the login form.
        val editorListener = TextView.OnEditorActionListener { _, id, _ ->
            if (id == EditorInfo.IME_ACTION_DONE || id == EditorInfo.IME_NULL) {
                attemptLogin()
                return@OnEditorActionListener true
            }
            false
        }
        password.setOnEditorActionListener(editorListener)
        password_confirm.setOnEditorActionListener(editorListener)

        signupswitch.setOnClickListener {
            isSignUp = !isSignUp
            updateUI();
        }

        if (Ramps.PASSWORDLESS_EXPERIENCE.getValue(activity) == true && showSuggested) {
            var user = viewModel.passwordlessAccount
            if (user != null) {
                findNavController().navigate(R.id.suggested_accounts_fragment,
                        null,
                        NavOptions.Builder().setPopUpTo(R.id.login_fragment, true).build())
            }
        }

        if (viewModel.usedAccounts.isNotEmpty())  {
            // suggest even expired accounts for autocomplete
            val adapter = ArrayAdapter(
                    view.context,
                    android.R.layout.simple_dropdown_item_1line,
                    viewModel.usedAccounts.toList())
            username.setAdapter(adapter)
            username.setOnClickListener {
                username.showDropDown()
            }
        }

         updateUI()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean(STATE_SIGNUP, isSignUp)
        super.onSaveInstanceState(outState)
    }

    private fun updateUI() {
        if (isSignUp) {
            password_confirm_layout.visibility = View.VISIBLE
            signupswitch.setText(R.string.already_have_an_account)
            sign_in_button.setText(R.string.sign_up)
        } else {
            password_confirm_layout.visibility = View.GONE
            signupswitch.setText(R.string.not_registered_an_account)
            sign_in_button.setText(R.string.action_sign_in)
        }
    }

    /**
     * Attempts to sign in or register the account specified by the login form.
     * If there are form errors (invalid email, missing fields, etc.), the
     * errors are presented and no actual login attempt is made.
     */
    private fun attemptLogin() {
        if (isInProgress()) {
            return
        }
        // Reset errors.
        username.error = null
        password.error = null

        // Store values at the time of the login attempt.
        val emailStr = username.text.toString()
        val passwordStr = password.text.toString()

        var cancel = false
        var focusView: View? = null

        // Check for a valid password, if the user entered one.
        if (TextUtils.isEmpty(passwordStr)) {
            password.error = getString(R.string.error_invalid_password)
            focusView = password
            cancel = true
        }

        if (isSignUp && !password_confirm.text.toString().equals(passwordStr)) {
            password.error = getString(R.string.error_incorrect_confirmed_password)
            focusView = password_confirm
            cancel = true
        }
        // Check for a valid email address.
        if (TextUtils.isEmpty(emailStr)) {
            username.error = getString(R.string.error_field_required)
            focusView = username
            cancel = true
      }

        if (cancel) {
            // There was an error; don't attempt login and focus the first
            // form field with an error.
            focusView?.requestFocus()
        } else {
            // Show a progress spinner, and kick off a background task to
            // perform the user login attempt.
            showProgress(true)
            if (isSignUp) {
                viewModel.signUp(emailStr, passwordStr)
            } else {
                viewModel.attemptLogin(emailStr, passwordStr)
            }
        }
    }

    override fun getLoginForm() = R.id.login_form
    override fun getLoginProgress() = R.id.login_progress
    override fun getFragmentId() = R.id.login_fragment

    override fun handleError(error: Throwable?) {
        error?.run {
            password.error = error.message
            Toast.makeText(context, error.message, Toast.LENGTH_LONG).show()
        } ?: run {
            password.error = null
        }
    }

    companion object {
        const val ARG_SHOW_SUGGESTED = "show"

        @JvmStatic
        fun getArguments(showSuggested: Boolean) = Bundle().apply {
            putInt(ARG_SHOW_SUGGESTED, if(showSuggested) 1 else 0)
        }
    }
}
