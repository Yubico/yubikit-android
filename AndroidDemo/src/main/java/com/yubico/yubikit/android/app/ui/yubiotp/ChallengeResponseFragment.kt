package com.yubico.yubikit.android.app.ui.yubiotp

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.core.util.RandomUtils
import com.yubico.yubikit.yubiotp.HmacSha1SlotConfiguration
import com.yubico.yubikit.yubiotp.StaticTicketSlotConfiguration
import kotlinx.android.synthetic.main.fragment_yubiotp_chalresp.*
import org.bouncycastle.util.encoders.Hex

class ChallengeResponseFragment : Fragment() {
    private val viewModel: OtpViewModel by activityViewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_yubiotp_chalresp, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        text_layout_key.setEndIconOnClickListener {
            edit_text_key.setText(String(Hex.encode(RandomUtils.getRandomBytes(8))))
        }
        edit_text_key.setText(String(Hex.encode(RandomUtils.getRandomBytes(8))))

        text_layout_challenge.setEndIconOnClickListener {
            edit_text_challenge.setText(String(Hex.encode(RandomUtils.getRandomBytes(8))))
        }
        edit_text_challenge.setText(String(Hex.encode(RandomUtils.getRandomBytes(8))))

        btn_save.setOnClickListener {
            try {
                val key = Hex.decode(edit_text_key.text.toString())
                val touch = switch_require_touch.isChecked
                val slot = when (slot_radio.checkedRadioButtonId) {
                    R.id.radio_slot_1 -> Slot.ONE
                    R.id.radio_slot_2 -> Slot.TWO
                    else -> throw IllegalStateException("No slot selected")
                }
                viewModel.pendingAction.value = {
                    putConfiguration(slot, HmacSha1SlotConfiguration(key).requireTouch(touch), null, null)
                    "Slot $slot programmed"
                }
            } catch (e: Exception) {
                viewModel.postResult(Result.failure(e))
            }
        }

        btn_calculate_response.setOnClickListener {
            try {
                val challenge = Hex.decode(edit_text_challenge.text.toString())
                val slot = when (slot_calculate_radio.checkedRadioButtonId) {
                    R.id.radio_calculate_slot_1 -> Slot.ONE
                    R.id.radio_calculate_slot_2 -> Slot.TWO
                    else -> throw IllegalStateException("No slot selected")
                }
                viewModel.pendingAction.value = {
                    val response = calculateHmacSha1(slot, challenge, null)
                    "Calculated response: " + String(Hex.encode(response))
                }
            } catch (e: java.lang.Exception) {
                viewModel.postResult(Result.failure(e))
            }
        }
    }
}