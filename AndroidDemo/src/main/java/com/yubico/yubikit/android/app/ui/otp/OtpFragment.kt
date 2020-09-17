package com.yubico.yubikit.android.app.ui.otp

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Observer
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.otp.Slot
import com.yubico.yubikit.otp.YubiOtpApplication
import kotlinx.android.synthetic.main.fragment_otp.*
import java.lang.IllegalStateException

class OtpFragment : YubiKeyFragment<YubiOtpApplication, OtpViewModel>() {
    override val viewModel: OtpViewModel by activityViewModels()

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_otp, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        pager.adapter = ProgramModeAdapter(this)

        TabLayoutMediator(tab_layout, pager) { tab, position ->
            tab.setText(when(position) {
                0 -> R.string.otp_yubiotp
                1 -> R.string.otp_chalresp
                else -> throw IllegalStateException()
            })
        }.attach()

        viewModel.slotConfigState.observe(viewLifecycleOwner, Observer {
            if (it != null) {
                empty_view.visibility = View.INVISIBLE
                otp_status_text.text = "Slot 1: ${if (it.slotIsConfigured(Slot.ONE)) "programmed" else "empty"}\nSlot 2: ${if (it.slotIsConfigured(Slot.TWO)) "programmed" else "empty"}"
                otp_status_text.visibility = View.VISIBLE
            } else {
                empty_view.visibility = View.VISIBLE
                otp_status_text.visibility = View.INVISIBLE
            }
        })
    }

    class ProgramModeAdapter(fragment: Fragment) : FragmentStateAdapter(fragment) {
        override fun getItemCount(): Int = 2

        override fun createFragment(position: Int): Fragment = when (position) {
            0 -> YubiOtpFragment()
            1 -> ChallengeResponseFragment()
            else -> throw IllegalStateException()
        }
    }
}