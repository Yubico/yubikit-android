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

package com.yubico.yubikit.demo.fido.network

import org.json.JSONException
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.net.HttpURLConnection

const val MESSAGE = "message"
/**
 * Callback that invoked
 */
abstract class ServiceCallback<T> : Callback<T> {

    fun handledErrorResponse(call: Call<T>, response: Response<T>) : Boolean {
        if (!response.isSuccessful || response.body() == null) {
            response.errorBody()?.let {
                var errorBodyString = it.string()
                val message = try {
                    var jsonObject = JSONObject(errorBodyString)
                    if (jsonObject.has(MESSAGE) && !jsonObject.isNull(MESSAGE)) {
                        jsonObject.getString(MESSAGE)
                    } else {
                        errorBodyString
                    }
                } catch (e: JSONException) {
                    errorBodyString
                }
                if(response.code() == HttpURLConnection.HTTP_NOT_FOUND) {
                    onFailure(call, ResourceNotFoundException(message))
                } else {
                    onFailure(call, DataException(message))
                }
            } ?: run {
                onFailure(call, DataException("body and errorBody are empty"))
            }
            return true
        }
        return false
    }
}
