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

package com.yubico.yubikit.utils;

/**
 * Helper singleton class allows to customize logs within SDK
 * SDK has only 2 levels of logging: debug information and error
 * If logger is not provided SDK won't produce any logs
 */
public class Logger {
    private static final Logger ourInstance = new Logger();

    public static Logger getInstance() {
        return ourInstance;
    }

    private Logger() {
    }

    private ILogger logger;
    public void setLogger(ILogger logger) {
        this.logger = logger;
    }

    public static void d(String message) {
        ILogger logger = getInstance().logger;
        if (logger == null) {
            return;
        }
        logger.logDebug(message);
    }

    public static void e(String message, Throwable throwable) {
        ILogger logger = getInstance().logger;
        if (logger == null) {
            return;
        }
        logger.logError(message, throwable);
    }

}
