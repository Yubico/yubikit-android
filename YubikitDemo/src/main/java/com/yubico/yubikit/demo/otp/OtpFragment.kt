package com.yubico.yubikit.demo.otp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.TextUtils
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast

import com.yubico.yubikit.demo.R
import com.yubico.yubikit.otp.OtpActivity
import kotlinx.android.synthetic.main.fragment_otp.*
import android.widget.ArrayAdapter
import android.content.Context
import android.text.Editable
import android.text.TextWatcher
import android.widget.TextView
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import com.yubico.yubikit.demo.fido.network.DataException

private const val OTP_REQUEST_CODE = 1
private const val VALID = "VALID"
private const val NOT_VALIDATED = "NOT_VALIDATED"
private const val SAVED_KEY = "key"
private const val SAVED_LOG = "log"
class OtpFragment : Fragment() {

    private val viewModel: OtpViewModel by lazy {
        ViewModelProviders.of(this, OtpViewModel.Factory(YubiCloudValidator())).get(OtpViewModel::class.java)
    }

    private lateinit var adapter: LogAdapter

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_otp, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = LogAdapter(view.context)
        output.setText(savedInstanceState?.getString(SAVED_KEY))
        output.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {
            }

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
            }

            override fun afterTextChanged(s: Editable?) {
                enableValidation(!TextUtils.isEmpty(s?.toString()))
            }
        })
        val logList = savedInstanceState?.getStringArrayList(SAVED_LOG)
        logList?.run {
            for (item in logList) {
                adapter.add(KeyValidation.parseFromString(item))
            }
        }

        start_demo.setOnClickListener {
            startActivityForResult(Intent(context, OtpActivity::class.java), OTP_REQUEST_CODE)
        }
        validate_otp.setOnClickListener {
            viewModel.validate(output.text.toString())
        }

        viewModel.success.observe(viewLifecycleOwner, Observer {
            val key = output.text.toString()
            adapter.add(KeyValidation(key, VALID))
            showLog(true)
        })
        viewModel.error.observe(viewLifecycleOwner, Observer {
            it ?: return@Observer
            val key = output.text.toString()
            when(it) {
                is DataException -> adapter.add(KeyValidation(key, it.message!!))
                else -> {
                    adapter.add(KeyValidation(key, NOT_VALIDATED))
                    Toast.makeText(context, it.message, Toast.LENGTH_LONG).show()
                }
            }
            showLog(true)
        })
    }

    override fun onResume() {
        super.onResume()
        output.requestFocus()
        enableValidation(!TextUtils.isEmpty(output.text.toString()))

        showLog(adapter.count != 0)
        otp_log.adapter = adapter
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == OTP_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                output.setText(data?.getStringExtra(OtpActivity.EXTRA_OTP))
                enableValidation(true)
            } else if (requestCode != Activity.RESULT_CANCELED && data != null) {
                val error = data.getSerializableExtra(OtpActivity.EXTRA_ERROR) as Throwable
                Toast.makeText(context, error.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(SAVED_KEY, output.text.toString())
        val logList = ArrayList<String>()
        for (i in 0 until adapter.count) {
            logList.add(adapter.getItem(i)!!.toString())
        }
        outState.putStringArrayList(SAVED_LOG, logList)
    }

    private fun enableValidation(visible: Boolean) {
        validate_otp.visibility = if(visible) View.VISIBLE else View.GONE
    }

    private fun showLog(visible: Boolean) {
        otp_log.visibility = if(visible) View.VISIBLE else View.GONE
    }

    class LogAdapter(context: Context) : ArrayAdapter<KeyValidation>(context, android.R.layout.simple_list_item_2, android.R.id.text1) {

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            var view = super.getView(position, convertView, parent)
            val text1 = view.findViewById(android.R.id.text1) as TextView
            val text2 = view.findViewById(android.R.id.text2) as TextView

            val validation = getItem(position)
            validation ?: return view

            text1.text = validation.key
            text2.text = validation.result
            text2.setTextColor(
                    if(VALID.equals(validation.result)) view.context.getColor(R.color.colorLightGreen) else view.context.getColor(android.R.color.holo_red_light))

            return view
        }
    }

    data class KeyValidation (val key: String, val result: String) {

        override fun toString() : String {
            return "$key:$result"
        }

        companion object {
            fun parseFromString(string: String) : KeyValidation {
                var parts = string.split(":")
                return KeyValidation(parts[0], parts[1])
            }
        }
    }
}
