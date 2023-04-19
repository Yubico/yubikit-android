/*
 * Copyright (C) 2023 Yubico.
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

import android.util.Log
import com.yubico.yubikit.core.Logger

class LoggerDemonstration {
    companion object {
        private val logger = org.slf4j.LoggerFactory.getLogger(LoggerDemonstration::class.java)
        fun run() {

            // log through slf4j
            log()

            Logger.setLogger(object : Logger() {
                override fun logDebug(message: String) {
                    Log.d("yubikit", message)
                }

                override fun logError(message: String, throwable: Throwable) {
                    Log.e("yubikit", message, throwable)
                }
            })

            // log through deprecated Logger
            log()

            // remove deprecated logger
            Logger.setLogger(null);
        }

        private fun log() {

            val throwable  = Throwable("THROWABLE")

            Logger.trace(logger, "logger.trace with no parameter")
            Logger.trace(logger, "logger.trace with 1 non-Throwable parameter: {}", "PARAM1")
            Logger.trace(logger, "logger.trace with 2 parameters: {}, {}", "PARAM1", "PARAM2")
            Logger.trace(logger, "logger.trace with 3 parameters: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3")
            Logger.trace(logger, "logger.trace with 1 Throwable parameter.", throwable)
            Logger.trace(logger, "logger.trace with 1 parameter and a Throwable: {}", "PARAM1", throwable)
            Logger.trace(logger, "logger.trace with 2 parameters and a Throwable: {}, {}", "PARAM1", "PARAM2", throwable)
            Logger.trace(logger, "logger.trace with 3 parameters and a Throwable: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3", throwable)

            Logger.debug(logger, "logger.debug with no parameter")
            Logger.debug(logger, "logger.debug with 1 non-Throwable parameter: {}", "PARAM1")
            Logger.debug(logger, "logger.debug with 2 parameters: {}, {}", "PARAM1", "PARAM2")
            Logger.debug(logger, "logger.debug with 3 parameters: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3")
            Logger.debug(logger, "logger.debug with 1 Throwable parameter.", throwable)
            Logger.debug(logger, "logger.debug with 1 parameter and a Throwable: {}", "PARAM1", throwable)
            Logger.debug(logger, "logger.debug with 2 parameters and a Throwable: {}, {}", "PARAM1", "PARAM2", throwable)
            Logger.debug(logger, "logger.debug with 3 parameters and a Throwable: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3", throwable)

            Logger.info(logger, "logger.info with no parameter")
            Logger.info(logger, "logger.info with 1 non-Throwable parameter: {}", "PARAM1")
            Logger.info(logger, "logger.info with 2 parameters: {}, {}", "PARAM1", "PARAM2")
            Logger.info(logger, "logger.info with 3 parameters: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3")
            Logger.info(logger, "logger.info with 1 Throwable parameter.", throwable)
            Logger.info(logger, "logger.info with 1 parameter and a Throwable: {}", "PARAM1", throwable)
            Logger.info(logger, "logger.info with 2 parameters and a Throwable: {}, {}", "PARAM1", "PARAM2", throwable)
            Logger.info(logger, "logger.info with 3 parameters and a Throwable: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3", throwable)

            Logger.warn(logger, "logger.warn with no parameter")
            Logger.warn(logger, "logger.warn with 1 non-Throwable parameter: {}", "PARAM1")
            Logger.warn(logger, "logger.warn with 2 parameters: {}, {}", "PARAM1", "PARAM2")
            Logger.warn(logger, "logger.warn with 3 parameters: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3")
            Logger.warn(logger, "logger.warn with 1 Throwable parameter.", throwable)
            Logger.warn(logger, "logger.warn with 1 parameter and a Throwable: {}", "PARAM1", throwable)
            Logger.warn(logger, "logger.warn with 2 parameters and a Throwable: {}, {}", "PARAM1", "PARAM2", throwable)
            Logger.warn(logger, "logger.warn with 3 parameters and a Throwable: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3", throwable)

            Logger.error(logger, "logger.error with no parameter")
            Logger.error(logger, "logger.error with 1 non-Throwable parameter: {}", "PARAM1")
            Logger.error(logger, "logger.error with 2 parameters: {}, {}", "PARAM1", "PARAM2")
            Logger.error(logger, "logger.error with 3 parameters: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3")
            Logger.error(logger, "logger.error with 1 Throwable parameter.", throwable)
            Logger.error(logger, "logger.error with 1 parameter and a Throwable: {}", "PARAM1", throwable)
            Logger.error(logger, "logger.error with 2 parameters and a Throwable: {}, {}", "PARAM1", "PARAM2", throwable)
            Logger.error(logger, "logger.error with 3 parameters and a Throwable: {}, {}, {}", "PARAM1", "PARAM2", "PARAM3", throwable)

            // this will not replace {} because the parameter is a Throwable
            Logger.debug(logger, "logger.debug with unexpected arguments: {}", throwable)
        }
    }
}