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

package com.yubico.yubikit.demo.oath

import android.os.CountDownTimer
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.fido.listview.OnRecyclerViewItemClickListener
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import com.yubico.yubikit.oath.OathType
import kotlinx.android.synthetic.main.oath_item_authenticator_list.view.*
import java.nio.ByteBuffer
import java.util.*

private const val MILLS_IN_SECOND = 1000.toLong()
class CredentialListAdapter(
        private val listener: OnRecyclerViewItemClickListener?)
    : ListAdapter<Pair<Credential, Code?>, CredentialListAdapter.ViewHolder>(COMPARATOR) {


    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.oath_item_authenticator_list, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val context = holder.view.context
        val item = getItem(position)
        holder.issuer.text = String.format(Locale.getDefault(),
                context.getString(R.string.issuer_format), item.first.name, item.first.issuer)
        holder.type.text = String.format(Locale.getDefault(), context.getString(R.string.type_format), item.first.oathType)

        val code = item.second
        if (SPECIAL_ISSUER_THAT_DOES_NOT_TRUNCATE_CODE == item.first.issuer && code != null) {
            // in case if provider requires different type of code to be shown
            holder.code.text = formatSteam(code)
        } else {
            holder.code.text = item.second?.value
        }

        // if it's TOTP and has generated code show progress bar
        if (code != null && item.first.oathType == OathType.TOTP) {
            holder.touchImage.visibility = View.GONE
            holder.progressBar.visibility = View.VISIBLE
            if (code.isValid) {
                holder.setProgressTimer(code.validUntil - System.currentTimeMillis())
            } else {
                holder.progressBar.progress = 100
            }
        } else {
            holder.progressBar.visibility = View.GONE
            holder.touchImage.visibility = if(item.first.isTouch) View.VISIBLE else View.GONE
        }
        with(holder.view) {
            setOnClickListener {
                listener?.onRecyclerViewItemClicked(holder.adapterPosition)
            }
        }
    }

    fun getItemData(position: Int): Pair<Credential, Code?> {
        return super.getItem(position)
    }

    inner class ViewHolder(val view: View) : RecyclerView.ViewHolder(view) {
        val issuer: TextView = view.issuer
        val type: TextView = view.type
        val code: TextView = view.code
        val progressBar: ProgressBar = view.progress
        val touchImage: ImageView = view.touch_image
        var timer: CountDownTimer? = null

        internal fun setProgressTimer(millsInFuture: Long) {
            timer?.cancel()
            timer = object : CountDownTimer(millsInFuture, MILLS_IN_SECOND) {
                override fun onFinish() {
                    progressBar.progress = 100
                }

                override fun onTick(millisUntilFinished: Long) {
                    progressBar.progress = ((millsInFuture - millisUntilFinished) * 100 / millsInFuture).toInt()
                }
            }
            timer?.start()
        }
    }

    companion object {
        private val COMPARATOR = object : DiffUtil.ItemCallback<Pair<Credential, Code?>>() {
            override fun areItemsTheSame(oldItem: Pair<Credential, Code?>, newItem: Pair<Credential, Code?>): Boolean =
                    oldItem.first.getId() == newItem.first.getId()

            override fun areContentsTheSame(oldItem: Pair<Credential, Code?>, newItem: Pair<Credential, Code?>): Boolean =
                    oldItem == newItem
        }

        private const val STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"
        private fun formatSteam(code: Code): String {
            var intCode = Integer.parseInt(code.value)
            return StringBuilder().apply {
                for (i in 0..4) {
                    append(STEAM_CHARS[intCode % STEAM_CHARS.length])
                    intCode /= STEAM_CHARS.length
                }

            }.toString()
        }
    }

}