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

package com.yubico.yubikit.demo.chresp

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.lifecycle.*
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.utils.StringUtils
import kotlinx.android.synthetic.main.fragment_challenge_response.*

private const val TAG = "ChallengeResponseFragment"
class ChallengeResponseFragment : BaseYubikeyFragment(TAG) {

    // this view model can be per fragment because we're not sharing it's data with any other activity or fragment
    private val viewModel: ChallengeResponseViewModel by lazy {
        ViewModelProviders.of(this,
                ChallengeResponseViewModel.Factory(YubiKitManager(activity!!.applicationContext)))
                .get(ChallengeResponseViewModel::class.java)
    }

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_challenge_response, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        generate.setOnClickListener {
            viewModel.resetResponse()
            challenge.setText(StringUtils.bytesToHex(viewModel.generateChallenge(8)).replace(" ", ""))
        }

        start_demo.setOnClickListener {
            if (hasConnection) {
                showProgress(true)
            }
            viewModel.resetResponse()
            viewModel.readResponse(challenge.text.toString())
        }

        viewModel.response.observe(viewLifecycleOwner, Observer {
            showProgress(false)
            it?.run {
                if (it.isEmpty()) {
                    Toast.makeText(context, "Response is empty. Make sure you configured secret for HMAC-SHA1 challenge-response", Toast.LENGTH_LONG).show()
                }
                response.text = StringUtils.bytesToHex(it)
            }
        })

        viewModel.requireTouch.observe(viewLifecycleOwner, Observer {
            if (it) {
                Toast.makeText(context, "Please touch the YubiKey button", Toast.LENGTH_LONG).show()
            }
        })
    }

    override fun onError(throwable: Throwable) {
        showProgress(false)
        when (throwable) {
            is ApduException -> {
                Log.e(TAG, "Status code : ${Integer.toHexString(throwable.statusCode)} ")
                Toast.makeText(activity, throwable.message, Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(activity, throwable.message, Toast.LENGTH_LONG).show()
            }
        }
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        // do not run demo unless user pressed button
    }

    override fun onNfcSession() {
        showProgress(true)
    }

    private fun showProgress(visible: Boolean) {
        progressBar.visibility = if (visible) View.VISIBLE else View.GONE
        hideAllSnackBars()
    }
}
