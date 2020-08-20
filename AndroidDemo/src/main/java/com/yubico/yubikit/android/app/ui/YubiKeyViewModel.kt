package com.yubico.yubikit.android.app.ui

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.android.YubiKeySession
import java.io.Closeable

abstract class YubiKeyViewModel<App : Closeable> : ViewModel() {
    private val _result = MutableLiveData<Result<String?>>(Result.success(null))
    val result: LiveData<Result<String?>> = _result

    val pendingAction = MutableLiveData<(App.() -> String?)?>()

    abstract fun getApp(session: YubiKeySession): App
    abstract fun App.updateState()

    fun onYubiKeySession(session: YubiKeySession) {
        try {
            getApp(session).use { app ->
                pendingAction.value?.let {
                    _result.postValue(Result.runCatching { it(app) })
                    pendingAction.postValue(null)
                }

                app.updateState()
            }
        } catch (e: Throwable) {
            _result.postValue(Result.failure(e))
        }
    }

    fun postResult(result: Result<String?>) {
        _result.postValue(result)
    }

    fun clearResult() {
        _result.value.let {
            if (it != null && (it.isFailure || it.getOrNull() != null)) {
                _result.postValue(Result.success(null))
            }
        }
    }
}