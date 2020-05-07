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

package com.yubico.yubikit.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

import androidx.core.view.GravityCompat
import androidx.navigation.NavController
import androidx.navigation.NavOptions
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.setupWithNavController
import kotlinx.android.synthetic.main.activity_main.*
import androidx.navigation.ui.onNavDestinationSelected
import com.yubico.yubikit.demo.settings.SettingsStorage


class MainActivity : AppCompatActivity() {

    private lateinit var navController: NavController
    private lateinit var settingsStorage: SettingsStorage

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // set theme before calling setContentView
        setTheme(R.style.AppTheme_NoActionBar)
        setContentView(R.layout.activity_main)
        // set up ActionBar
        setSupportActionBar(toolbar)

        settingsStorage = SettingsStorage(this)
        navController = findNavController(R.id.fragment_container)
        nav_view.setupWithNavController(navController)
        nav_view.setNavigationItemSelectedListener {
            drawer_layout.closeDrawer(GravityCompat.START)

            // save selected navigation drawer pivot (only demo pivots are interesting, skipping Settings)
            if (it.groupId == R.id.menu_top) {
                settingsStorage.saveNavigationDestination(it.itemId)
            }

            val popupId = navController.currentDestination?.id ?: R.id.piv_fragment
            navController.navigate(it.itemId, null, NavOptions.Builder().setPopUpTo(popupId, true).build())
            it.onNavDestinationSelected(navController)
        }
        val appBarConfiguration = AppBarConfiguration(setOf(
                R.id.oath_fragment,
                R.id.yubico_otp_fragment,
                R.id.mgmt_fragment,
                R.id.piv_fragment,
                R.id.configure_otp_fragment,
                R.id.challenge_fragment), drawer_layout)

        toolbar.setupWithNavController(navController, appBarConfiguration)

        // if user opened demo app for the first time show him variation of demos on navigation drawer
        if (settingsStorage.isFirstTimeExperience()) {
            drawer_layout.openDrawer(GravityCompat.START)
            settingsStorage.markApplicationVisited()
        }
    }

    // close nav drawer on back pressed
    override fun onBackPressed() {
        if (drawer_layout.isDrawerOpen(GravityCompat.START)) {
            drawer_layout.closeDrawer(GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }
}
