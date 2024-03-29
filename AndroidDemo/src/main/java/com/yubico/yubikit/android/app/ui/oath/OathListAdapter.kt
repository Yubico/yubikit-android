/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.android.app.ui.oath

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import java.util.*

class OathListAdapter(private val listener: ItemListener) : ListAdapter<Pair<Credential, Code?>, OathListAdapter.ViewHolder>(object : DiffUtil.ItemCallback<Pair<Credential, Code?>>() {
    override fun areItemsTheSame(oldItem: Pair<Credential, Code?>, newItem: Pair<Credential, Code?>): Boolean {
        return Arrays.equals(oldItem.first.id, newItem.first.id)
    }

    override fun areContentsTheSame(oldItem: Pair<Credential, Code?>, newItem: Pair<Credential, Code?>): Boolean {
        return oldItem.second?.value == newItem.second?.value
    }
}) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.listitem_oath_entry, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        getItem(position).let { (credential, code) ->
            with(holder) {
                idView.text = credential.issuer?.let { "$it (${credential.accountName})" }
                        ?: credential.accountName
                contentView.text = code?.value ?: ""
                deleteBtn.setOnClickListener {
                    listener.onDelete(credential.id)
                }
            }
        }
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val idView: TextView = view.findViewById(R.id.item_number)
        val contentView: TextView = view.findViewById(R.id.content)
        val deleteBtn: Button = view.findViewById(R.id.btn_delete)
    }

    interface ItemListener {
        fun onDelete(credentialId: ByteArray)
    }
}