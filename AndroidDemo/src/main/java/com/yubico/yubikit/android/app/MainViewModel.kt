package com.yubico.yubikit.android.app

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

class MainViewModel() : ViewModel() {
    val singleDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    private val _handleYubiKey = MutableLiveData(true)
    val handleYubiKey: LiveData<Boolean> = _handleYubiKey

    fun setYubiKeyListenerEnabled(enabled: Boolean) {
        _handleYubiKey.postValue(enabled)
    }

    val yubiKey = MutableLiveData<YubiKeyDevice?>()
}