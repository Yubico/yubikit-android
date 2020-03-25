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

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Toast
import androidx.annotation.IdRes
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.yubico.yubikit.demo.fido.R
import com.yubico.yubikit.demo.fido.communication.ApiUtils
import com.yubico.yubikit.demo.fido.Fido2ViewModel
import com.yubico.yubikit.fido.Fido2ClientApi

abstract class BaseLoginFragment : Fragment() {

    protected lateinit var viewModel: LoginViewModel
    private lateinit var fido2ViewModel : Fido2ViewModel
    private var isInProgress = false

    private val login_form : ScrollView by lazy {
        view?.findViewById(getLoginForm()) as ScrollView
    }

    private val login_progress : ProgressBar by lazy {
        view?.findViewById(getLoginProgress()) as ProgressBar
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        activity?.let {
            // this is shared view models, require passing activity (not fragment)
            viewModel = ViewModelProviders.of(it, LoginViewModel.Factory(
                    ApiUtils.getApiService(),
                    AccountStorage(it.applicationContext))).get(LoginViewModel::class.java)

            // not shared view model (other fragments use their own fido2 view models)
            fido2ViewModel = ViewModelProviders.of(this, Fido2ViewModel.Factory(Fido2ClientApi(it.applicationContext))).get(Fido2ViewModel::class.java)
        }

        viewModel.signedUser.observe(viewLifecycleOwner, Observer {
            showProgress(false)
            it?.run {
                findNavController().navigate(
                        R.id.main_fragment,
                        UserDataBundle(it).bundle,
                        NavOptions.Builder().setPopUpTo(getFragmentId(),true).build())
            } ?: run {

            }
        })
        viewModel.error.observe(viewLifecycleOwner, Observer {
            handleError(it)
            it?.run {
                showProgress(false)
            }
        })
        viewModel.getAssertionOptions.observe(viewLifecycleOwner, Observer {
            it?.run {
                fido2ViewModel.authenticateWithKey(it)
            }
        })

        viewModel.makeCredentialOptions.observe(viewLifecycleOwner, Observer {
            it?.run {
                fido2ViewModel.registerKey(it)
            }
        })

        fido2ViewModel.requestCode.observe(viewLifecycleOwner, Observer {
            it?.run {
                fido2ViewModel.launch(this@BaseLoginFragment)
            }
        })

        fido2ViewModel.assertionResponse.observe(viewLifecycleOwner, Observer {
            it?.run {
                viewModel.authenticateFinish(it.keyHandle, it.authenticatorData, it.clientDataJSON, it.signature, it.userHandle)
            }
        })

        fido2ViewModel.makeCredentialResponse.observe(viewLifecycleOwner, Observer {
            it?.run {
                viewModel.registerFinish(it.keyHandle, it.attestationObject, it.clientDataJSON)
            }
        })

        fido2ViewModel.error.observe(viewLifecycleOwner, Observer {
            it?.run {
                showProgress(false)
                Toast.makeText(context, it.message, Toast.LENGTH_LONG).show()
            }
        })
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        fido2ViewModel.onActivityResult(requestCode, resultCode, data)
    }

    protected fun showProgress(show: Boolean) {
        isInProgress = show
        login_progress.visibility = if (show) View.VISIBLE else View.GONE
        login_form.visibility = if (show) View.GONE else View.VISIBLE
    }

    protected fun isInProgress() = isInProgress

    @IdRes
    abstract fun getLoginForm() : Int
    @IdRes
    abstract fun getLoginProgress() : Int
    @IdRes
    abstract fun getFragmentId() : Int

    abstract fun handleError(error: Throwable?)
}