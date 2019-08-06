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

import androidx.recyclerview.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter


import com.yubico.yubikit.demo.fido.R
import com.yubico.yubikit.fido.AuthenticatorAttachment

import kotlinx.android.synthetic.main.item_authenticator_list.view.*
import java.text.SimpleDateFormat
import java.util.*

/**
 * [RecyclerView.Adapter] that can display a [AuthenticatorItem] and makes a call to the
 * specified [OnRecyclerViewItemClickListener].
 */
class AuthenticatorListAdapter(
        private val mListener: OnRecyclerViewItemClickListener?)
    : ListAdapter<AuthenticatorItem, AuthenticatorListAdapter.ViewHolder>(COMPARATOR) {

    private val DATE_FORMAT = SimpleDateFormat("MM/dd/yyyy HH:mm:ss", Locale.getDefault())

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_authenticator_list, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val context = holder.view.context;
        val item = getItem(position)
        holder.name.text = item.name
        holder.added.text = String.format(Locale.getDefault(), context.getString(R.string.added_format), DATE_FORMAT.format(item.registeredAt))
        holder.used.text = String.format(Locale.getDefault(), context.getString(R.string.used_format), DATE_FORMAT.format(item.lastUsed))

        holder.icon.setImageResource(
                if (item.authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM)
                R.drawable.ic_yubikey_icon else R.drawable.ic_fingerprint)
        with(holder.view) {
            setOnClickListener {
                // Notify the active callbacks interface (the activity, if the fragment is attached to
                // one) that an item has been selected.
                mListener?.onRecyclerViewItemClicked(holder.adapterPosition)
            }
        }
    }

    inner class ViewHolder(val view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.icon
        val name: TextView = view.name
        val added: TextView = view.added
        val used: TextView = view.used    }

    fun getItemData(position: Int): AuthenticatorItem {
        return super.getItem(position)
    }

    companion object {
        private val COMPARATOR = object : DiffUtil.ItemCallback<AuthenticatorItem>() {
            override fun areItemsTheSame(oldItem: AuthenticatorItem, newItem: AuthenticatorItem): Boolean =
                    oldItem.id == newItem.id

            override fun areContentsTheSame(oldItem: AuthenticatorItem, newItem: AuthenticatorItem): Boolean =
                    oldItem == newItem
        }
    }
}
