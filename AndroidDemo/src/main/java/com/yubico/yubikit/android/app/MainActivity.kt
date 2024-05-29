/*
 * Copyright (C) 2022-2023 Yubico.
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

package com.yubico.yubikit.android.app

import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.drawerlayout.widget.DrawerLayout
import androidx.navigation.NavController
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.navigation.NavigationView
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.app.databinding.DialogAboutBinding
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import java.security.Security
import java.util.Locale
import kotlin.properties.Delegates

class MainActivity : AppCompatActivity() {
    private val logger = LoggerFactory.getLogger(MainActivity::class.java)
    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var navController: NavController

    private val viewModel: MainViewModel by viewModels()

    private lateinit var yubikit: YubiKitManager
    private val nfcConfiguration = NfcConfiguration().timeout(15000)

    private var hasNfc by Delegates.notNull<Boolean>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // needed for Ed25519 and X25519
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())

        val toolbar: Toolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)

        val drawerLayout: DrawerLayout = findViewById(R.id.drawer_layout)
        val navView: NavigationView = findViewById(R.id.nav_view)
        navController = findNavController(R.id.nav_host_fragment)
        // Passing each menu ID as a set of Ids because each
        // menu should be considered as top level destinations.
        appBarConfiguration = AppBarConfiguration(setOf(
                R.id.nav_management, R.id.nav_yubiotp, R.id.nav_piv, R.id.nav_oath), drawerLayout)
        setupActionBarWithNavController(navController, appBarConfiguration)
        navView.setupWithNavController(navController)

        yubikit = YubiKitManager(this)

        viewModel.handleYubiKey.observe(this) {
            if (it) {
                logger.info("Enable listening")
                yubikit.startUsbDiscovery(UsbConfiguration()) { device ->
                    logger.info("USB device attached {}, current: {}", device, viewModel.yubiKey.value)
                    viewModel.yubiKey.postValue(device)
                    device.setOnClosed {
                        logger.info("Device removed {}", device)
                        viewModel.yubiKey.postValue(null)
                    }
                }
                try {
                    yubikit.startNfcDiscovery(nfcConfiguration, this) { device ->
                        logger.info("NFC Session started {}", device)
                        viewModel.yubiKey.apply {
                            // Trigger new value, then removal
                            runOnUiThread {
                                value = device
                                postValue(null)
                            }
                        }
                    }
                    hasNfc = true
                } catch (e: NfcNotAvailable) {
                    hasNfc = false
                    logger.error("Error starting NFC listening", e)
                }
            } else {
                logger.info("Disable listening")
                yubikit.stopNfcDiscovery(this)
                yubikit.stopUsbDiscovery()
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_about -> {
                val binding = DialogAboutBinding.inflate(LayoutInflater.from(this))
                AlertDialog.Builder(this)
                        .setView(binding.root)
                        .create().apply {
                            setOnShowListener {
                                binding.version.text = String.format(Locale.getDefault(), getString(R.string.version), BuildConfig.VERSION_NAME)
                            }
                        }.show()
            }
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onSupportNavigateUp(): Boolean {
        return navController.navigateUp(appBarConfiguration) || super.onSupportNavigateUp()
    }

    override fun onResume() {
        super.onResume()
        if (viewModel.handleYubiKey.value == true && hasNfc) {
            try {
                yubikit.startNfcDiscovery(nfcConfiguration, this) { device ->
                    logger.info("NFC device connected {}", device)
                    viewModel.yubiKey.apply {
                        // Trigger new value, then removal
                        runOnUiThread {
                            value = device
                            postValue(null)
                        }
                    }
                }
            } catch (e: NfcNotAvailable) {
                logger.error("NFC is not available", e)
            }
        }
    }

    override fun onPause() {
        yubikit.stopNfcDiscovery(this)
        super.onPause()
    }

    override fun onDestroy() {
        viewModel.yubiKey.value = null
        yubikit.stopUsbDiscovery()
        super.onDestroy()
    }
}