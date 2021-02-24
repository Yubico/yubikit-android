package com.yubico.yubikit.android.app.ui.yubiotp

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.databinding.FragmentYubiotpBinding
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession

class OtpFragment : YubiKeyFragment<YubiOtpSession, OtpViewModel>() {
    override val viewModel: OtpViewModel by activityViewModels()
    private lateinit var binding: FragmentYubiotpBinding

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        binding = FragmentYubiotpBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.pager.adapter = ProgramModeAdapter(this)

        TabLayoutMediator(binding.tabLayout, binding.pager) { tab, position ->
            tab.setText(when (position) {
                0 -> R.string.otp_yubiotp
                1 -> R.string.otp_chalresp
                else -> throw IllegalStateException()
            })
        }.attach()

        viewModel.slotConfigurationState.observe(viewLifecycleOwner, {
            if (it != null) {
                binding.emptyView.visibility = View.INVISIBLE
                binding.otpStatusText.text = "Slot 1: ${if (it.isConfigured(Slot.ONE)) "programmed" else "empty"}\nSlot 2: ${if (it.isConfigured(Slot.TWO)) "programmed" else "empty"}"
                binding.otpStatusText.visibility = View.VISIBLE
            } else {
                binding.emptyView.visibility = View.VISIBLE
                binding.otpStatusText.visibility = View.INVISIBLE
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