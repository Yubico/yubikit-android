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

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.*
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.yubico.yubikit.demo.R
import kotlinx.android.synthetic.main.fragment_piv.*
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentPagerAdapter
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import androidx.navigation.fragment.findNavController
import androidx.navigation.ui.onNavDestinationSelected
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.oath.AuthRequiredException
import com.yubico.yubikit.demo.oath.PasswordDialogFragment
import com.yubico.yubikit.demo.settings.Ramps
import com.yubico.yubikit.piv.Slot

private const val TAG = "PivFragment"
class PivFragment : BaseYubikeyFragment(TAG), PasswordDialogFragment.DialogListener, RetriesDialogFragment.DialogListener {
    /**
     * Mapping between app type and user friendly name of that type
     */
    private val slots = listOf(PageProperties(Slot.AUTHENTICATION, R.string.piv_authentication),
            PageProperties(Slot.SIGNATURE, R.string.piv_signature),
            PageProperties(Slot.KEY_MANAGEMENT, R.string.piv_key_mgmt),
            PageProperties(Slot.CARD_AUTH, R.string.piv_card_auth))

    // this view model shared between fragments
    private val viewModel: PivViewModel by lazy {
        val context = activity!!.applicationContext
        ViewModelProviders.of(activity!!,
                PivViewModel.Factory(YubiKitManager(context), Settings(context)))
                .get(PivViewModel::class.java)
    }

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_piv, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        pager.adapter = PagerAdapter(childFragmentManager)
        tab_layout.setupWithViewPager(pager)
        showCerts(false)

        viewModel.operationStarted.observe(viewLifecycleOwner, Observer {
            it?: return@Observer
            showProgress(true)
            Log.d(TAG, it)
        })
        viewModel.operationCompleted.observe(viewLifecycleOwner, Observer {
            it?: return@Observer
            showProgress(false)
            Log.d(TAG, it)
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
        })

        viewModel.requireAuth.observe(viewLifecycleOwner, Observer {
            it?: return@Observer
            if (it == PasswordDialogFragment.PasswordType.MGMT_KEY && Ramps.PIV_USE_DEFAULT_MGMT.getValue(context) == true) {
                viewModel.authenticate(DEFAULT_AUTH_KEY)
            } else {
                PasswordDialogFragment.newInstance(true, true, it, getDefaultValue(it)).show(childFragmentManager, "password")
            }
        })

        viewModel.certificates.observe(viewLifecycleOwner, Observer {
            it?.run {
                showCerts(true)
            }
        })
    }

    override fun onError(throwable: Throwable) {
        when (throwable) {
            is ApduException -> {
                Log.e(TAG, "Status code : ${Integer.toHexString(throwable.statusCode)} ")
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
            is AuthRequiredException -> {
                // prompt for password
                PasswordDialogFragment.newInstance(true, true, throwable.passwordType, getDefaultValue(throwable.passwordType)).show(childFragmentManager, "password")
            }
            is ApduException -> {
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(context, throwable.message, Toast.LENGTH_LONG).show()
            }
        }
        showProgress(false)
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        if (hasPermissions) {
            viewModel.executeDemoCommands()
        }
    }

    override fun onNfcSession() {
    }


    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.piv_toolbar_menu, menu)
    }

    override fun onPrepareOptionsMenu(menu: Menu) {
        super.onPrepareOptionsMenu(menu)
        val showMenu = viewModel.certificates.value != null
        for (i in 0 until menu.size()) {
            menu.getItem(i).isVisible = showMenu
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when(item.itemId) {
            R.id.action_pin -> {
                PasswordDialogFragment.newInstance(false, true, PasswordDialogFragment.PasswordType.PIN, DEFAULT_PIN).show(childFragmentManager, "password")
                return true
            }
            R.id.action_puk -> {
                PasswordDialogFragment.newInstance(false, true, PasswordDialogFragment.PasswordType.PUK, DEFAULT_PUK).show(childFragmentManager, "password")
                return true
            }
            R.id.action_mgmt_key -> {
                PasswordDialogFragment.newInstance(false, true, PasswordDialogFragment.PasswordType.MGMT_KEY, DEFAULT_AUTH_KEY).show(childFragmentManager, "password")
                return true
            }
            R.id.action_retries -> {
                RetriesDialogFragment.newInstance(DEFAULT_PIN).show(childFragmentManager, "retries")
                return true
            }
            R.id.action_unblock -> {
                PasswordDialogFragment.newInstance(false, true, PasswordDialogFragment.PasswordType.UNBLOCK, DEFAULT_PUK).show(childFragmentManager, "password")
                return true
            }
            R.id.action_reset -> {
                viewModel.reset()
                return true
            }
        }
        return item.onNavDestinationSelected(findNavController()) || super.onOptionsItemSelected(item)
    }

    override fun onPasswordProvided(password: String, passwordType: PasswordDialogFragment.PasswordType) {
        when(passwordType) {
            PasswordDialogFragment.PasswordType.PIN -> viewModel.verify(password)
            else -> viewModel.authenticate(password)
        }
    }

    override fun onPasswordChanged(password: String, newPassword: String, passwordType: PasswordDialogFragment.PasswordType) {
        when(passwordType) {
            PasswordDialogFragment.PasswordType.UNBLOCK -> viewModel.unblockPin(password, newPassword)
            else -> viewModel.changePassword(password, newPassword, passwordType)
        }
    }

    override fun onPinProvided(pin: String, pinRetries: Int, pukRetries: Int) {
        viewModel.changeRetries(pin, pinRetries, pukRetries)
    }

    override fun onCancel() {
        viewModel.clearTasks()
    }

    private fun showCerts(visible: Boolean) {
        pager.visibility = if (visible) View.VISIBLE else View.GONE
        empty_list.visibility = if (visible) View.GONE else View.VISIBLE
        showProgress(false)
        activity?.invalidateOptionsMenu()
    }

    private fun showProgress(visible: Boolean) {
        progressBarText.visibility = if (visible && !hasConnection) View.VISIBLE else View.GONE
        progress.visibility = if (visible) View.VISIBLE else View.GONE
        hideAllSnackBars()
    }

    private fun getDefaultValue(passwordType: PasswordDialogFragment.PasswordType) : String {
        return when(passwordType) {
            PasswordDialogFragment.PasswordType.PIN -> DEFAULT_PIN
            PasswordDialogFragment.PasswordType.PUK -> DEFAULT_PUK
            else -> DEFAULT_AUTH_KEY
        }
    }

    // Since this is an object collection, use a FragmentStatePagerAdapter,
    // and NOT a FragmentPagerAdapter.
    inner class PagerAdapter(fragmentManager: FragmentManager) : FragmentPagerAdapter(fragmentManager, BEHAVIOR_RESUME_ONLY_CURRENT_FRAGMENT) {
        override fun getItem(position: Int): Fragment {
            return PivCertificateFragment.newInstance(slots[position].slot, slots[position].nameResId)
        }

        override fun getPageTitle(position: Int): CharSequence? {
            return String.format("Slot %02X", slots[position].slot.value)
        }

        override fun getCount(): Int {
            return slots.size
        }
    }

    private class Settings(private val context: Context) : ISettings {
        override val connectionTimeout: Int
            get() = Ramps.CONNECTION_TIMEOUT.getValue(context) as Int
    }


    private data class PageProperties(val slot: Slot, val nameResId: Int)
}