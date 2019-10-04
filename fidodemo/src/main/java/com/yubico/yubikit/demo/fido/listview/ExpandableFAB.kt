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
import android.util.AttributeSet
import android.view.View
import android.widget.FrameLayout
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.yubico.yubikit.demo.fido.R
import kotlinx.android.synthetic.main.expandable_fab.view.*


/**
 * FAB button for registration of new authenticator that expands with 2 options: fingerprint or key
 */
class ExpandableFAB : FrameLayout {

    private var isExpandable = true
    private var isFABOpen = false
    private var listener: Listener? = null

    constructor(context: Context) : super(context) {
        init(null, 0)
    }

    constructor(context: Context, attrs: AttributeSet) : super(context, attrs) {
        init(attrs, 0)
    }

    constructor(context: Context, attrs: AttributeSet, defStyle: Int) : super(context, attrs, defStyle) {
        init(attrs, defStyle)
    }

    private fun init(attrs: AttributeSet?, defStyle: Int) {
        // Load attributes
        val a = context.obtainStyledAttributes(
                attrs, R.styleable.ExpandableFAB, defStyle, 0)
        a.recycle()

        inflate(context, R.layout.expandable_fab, this)
        fab.setOnClickListener {
            if (isExpandable) {
                if (!isFABOpen) {
                    showFABMenu();
                } else {
                    closeFABMenu();
                }
            } else {
                listener?.onOperationsClicked(1)
            }
        }
        fab1.setOnClickListener {
            closeFABMenu()
            listener?.onOperationsClicked(0)
        }
        fab2.setOnClickListener {
            closeFABMenu()
            listener?.onOperationsClicked(1)
        }
        shadowView.setOnClickListener {
            closeFABMenu()
        }
    }

    fun makeExpandable(expandable: Boolean) {
        isExpandable = expandable
    }

    fun setOnClickLister(l: Listener?) {
        listener = l
    }

    private fun showFABMenu() {
        isFABOpen = true
        setFABMenuItemVisible(fab1, -resources.getDimension(R.dimen.fab1_margin), true)
        setFABMenuItemVisible(fab2, -resources.getDimension(R.dimen.fab2_margin), true)
        fab.animate().rotation(45f)
        shadowView.visibility = View.VISIBLE
    }

    private fun closeFABMenu() {
        isFABOpen = false

        setFABMenuItemVisible(fab1, 0f, false)
        setFABMenuItemVisible(fab2, 0f, false)
        fab.animate().rotation(0f)
        shadowView.visibility = View.GONE
    }

    private fun setFABMenuItemVisible(fab: FloatingActionButton, value: Float, visible: Boolean) {
        if (visible) {
            fab.show()
            fab.animate().translationY(value)
        } else {
            fab.animate().translationY(value)
                    .withEndAction { fab.hide() }
        }
    }

    interface Listener {
        fun onOperationsClicked(position: Int)
    }
}
