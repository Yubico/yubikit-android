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

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import com.yubico.yubikit.demo.fido.arch.Injection
import com.yubico.yubikit.demo.fido.communication.ApiUtils
import com.yubico.yubikit.demo.fido.communication.User
import com.yubico.yubikit.demo.fido.Fido2ViewModel
import com.yubico.yubikit.demo.fido.signin.UserDataBundle

/**
 * Base Fragment class that has userData in arguments for creation
 * And handles FIDO queries if registerFidoObserver is true:
 * registers fido observers to listen registration/assertion requests from server
 * and sends back responses from authenticator to backend
 *
 * Easy usage: derive from this class and invoke {@link viewModel#registerKey or viewModel#authenticateWithKey}
 */
open class UserDataFragment(private val registerFidoObserver: Boolean = true) : Fragment() {

    private val appContext by lazy {
        view!!.context.applicationContext
    }
    private val fidoClient by lazy {
        Injection.provideFidoClient(appContext)
    }
    private val localCache by lazy {
        Injection.provideCache(appContext)
    }

    protected val networkService = ApiUtils.getApiService()
    protected val accountStorage by lazy {
        Injection.provideAccountStorage(appContext)
    }

    // user object that received with arguments to fragment
    protected lateinit var userData: User

    protected val viewModel: AuthenticatorModel by lazy {
        // this view is per fragment, because we create another 1 for another user
        ViewModelProviders.of(this, AuthenticatorModel.Factory(
                networkService,
                localCache,
                accountStorage,
                userData)).get(AuthenticatorModel::class.java)
    }

    protected val fido2ViewModel : Fido2ViewModel by lazy {
        // this view is per fragment
        ViewModelProviders.of(this, Fido2ViewModel.Factory(fidoClient)).get(Fido2ViewModel::class.java)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        userData = UserDataBundle.getUserData(arguments)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        if (registerFidoObserver) {
            viewModel.makeCredentialOptions.observe(viewLifecycleOwner, Observer {
                it?.run {
                    fido2ViewModel.registerKey(it)
                }
            })

            fido2ViewModel.requestCode.observe(viewLifecycleOwner, Observer {
                it?.run {
                    activity?.run {
                        fido2ViewModel.launch(this)
                    }
                }
            })

            fido2ViewModel.makeCredentialResponse.observe(viewLifecycleOwner, Observer {
                it?.run {
                    viewModel.registerFinish(it.keyHandle, it.attestationObject, it.clientDataJSON)

                }
            })

            viewModel.getAssertionOptions.observe(viewLifecycleOwner, Observer {
                it?.run {
                    fido2ViewModel.authenticateWithKey(it)
                }
            })

            fido2ViewModel.assertionResponse.observe(viewLifecycleOwner, Observer {
                it?.run {
                    viewModel.authenticateFinish(
                        it.keyHandle,
                        it.authenticatorData,
                        it.clientDataJSON,
                        it.signature,
                        it.userHandle
                    )
                }
            })

            fido2ViewModel.error.observe(viewLifecycleOwner, Observer {
                it?.run {
                    handleError(it)
                }
            })
        }

        viewModel.error.observe(viewLifecycleOwner, Observer {
            it?.run {
                handleError(it)
            }
        })
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (registerFidoObserver) {
            fido2ViewModel.onActivityResult(requestCode, resultCode, data)
        }
    }

    protected open fun handleError(e: Throwable) {
        //override that method to have proper error handler
    }

    protected fun getArgumentsBundle() : Bundle {
        return UserDataBundle(userData).bundle
    }
}