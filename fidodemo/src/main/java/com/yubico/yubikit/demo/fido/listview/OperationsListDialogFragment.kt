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

import android.content.Context
import android.os.Bundle
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.annotation.IdRes
import com.yubico.yubikit.demo.fido.R;
import kotlinx.android.synthetic.main.fragment_operations_list_dialog.*
import kotlinx.android.synthetic.main.item_operations_list.view.*

/**
 *
 * A fragment that shows a list of items as a modal bottom sheet.
 *
 * You can show this modal bottom sheet from your activity like this:
 * <pre>
 *    OperationsListDialogFragment.newInstance(30).show(supportFragmentManager, "dialog")
 * </pre>
 *
 * You activity (or fragment) needs to implement [OperationsListDialogFragment.Listener].
 */
class OperationsListDialogFragment : BottomSheetDialogFragment() {
    private var listener: Listener? = null
    private var selectedItemPosition: Int? = null
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_operations_list_dialog, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        require(arguments != null) {"Use OperationsListDialogFragment.newInstance() method to create this fragment"}
        val arrayOperationLogos = arguments?.getInt(ARG_LOGO)
        require(arrayOperationLogos != null) {"Use OperationsListDialogFragment.newInstance() method to create this fragment"}
        val arrayOperationNames = arguments?.getInt(ARG_NAMES)
        require(arrayOperationNames != null) {"Use OperationsListDialogFragment.newInstance() method to create this fragment"}
        selectedItemPosition = arguments?.getInt(ARG_SELECTED_ITEM)
        require(selectedItemPosition != null) {"Use OperationsListDialogFragment.newInstance() method to create this fragment"}

        list.apply {
            layoutManager = LinearLayoutManager(context)
            val logos = resources.obtainTypedArray(arrayOperationLogos)
            adapter = OperationsAdapter(resources.getStringArray(arrayOperationNames).mapIndexed { index, op -> Operation(op, logos.getResourceId(index, 0)) })
            logos.recycle()
        }

    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        val parent = parentFragment
        if (parent != null) {
            listener = parent as Listener
        } else {
            listener = context as Listener
        }
    }

    override fun onDetach() {
        listener = null
        super.onDetach()
    }

    interface Listener {
        fun onOperationsClicked(oparationPosition: Int, itemPosition: Int)
    }

    private inner class ViewHolder internal constructor(inflater: LayoutInflater, parent: ViewGroup)
        : RecyclerView.ViewHolder(inflater.inflate(R.layout.item_operations_list, parent, false)) {
        internal val text: TextView = itemView.text
    }

    private inner class OperationsAdapter internal constructor(private val operations : List<Operation>) : RecyclerView.Adapter<ViewHolder>() {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(LayoutInflater.from(parent.context), parent)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.text.text = operations[position].name
            holder.text.setCompoundDrawablesWithIntrinsicBounds(operations[position].resId, 0,0,0)
            holder.text.setOnClickListener {
                dismiss()
                listener?.let {
                    it.onOperationsClicked(holder.adapterPosition, selectedItemPosition!!)
                }
            }
        }

        override fun getItemCount(): Int {
            return operations.size
        }
    }

    data class Operation (val name: String, @DrawableRes val resId: Int)


    companion object {
        const val ARG_LOGO = "logosId"
        const val ARG_NAMES = "namesId"
        const val ARG_SELECTED_ITEM = "selectedItemPosition"
        fun newInstance(logosId: Int, namesId: Int, position: Int): OperationsListDialogFragment =
                OperationsListDialogFragment().apply {
                    arguments = Bundle().apply {
                        putInt(ARG_LOGO, logosId)
                        putInt(ARG_NAMES, namesId)
                        putInt(ARG_SELECTED_ITEM, position)
                    }
                }

    }
}
