/*
 * Copyright (C) 2019-2022 Yubico.
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

package com.yubico.yubikit.core;


import org.slf4j.event.Level;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;

import javax.annotation.Nullable;

/**
 * Helper class allows to customize logs within the SDK
 * SDK has only 2 levels of logging: debug information and error
 * If a Logger implementation is not provided the SDK won't produce any logs
 *
 * @see <a href="https://github.com/Yubico/yubikit-android/blob/main/doc/Logging_Migration.adoc">Logging Migration</a>
 * contains information about logging in YubiKit, best practices and migration from Logger.
 * @deprecated This class and all its public methods have been deprecated in YubiKit 2.3.0 and will be removed
 * in future release.
 */
@Deprecated
public abstract class Logger {

    public static final class Internal {
        private static void log(Level level, org.slf4j.Logger logger, String message) {
            if (instance != null) {
                if (Level.ERROR == level) {
                    instance.logError(message, new Exception("Throwable missing in logger.error"));
                } else {
                    instance.logDebug(message);
                }
            } else {
                switch (level) {
                    case TRACE:
                        logger.trace(message);
                        break;
                    case DEBUG:
                        logger.debug(message);
                        break;
                    case INFO:
                        logger.info(message);
                        break;
                    case WARN:
                        logger.warn(message);
                        break;
                    case ERROR:
                        logger.error(message);
                        break;
                }
            }
        }

        private static void log(Level level, org.slf4j.Logger logger, String format, Object arg) {
            if (instance != null) {
                logToInstance(level, MessageFormatter.format(format, arg));
            } else {
                switch (level) {
                    case TRACE:
                        logger.trace(format, arg);
                        break;
                    case DEBUG:
                        logger.debug(format, arg);
                        break;
                    case INFO:
                        logger.info(format, arg);
                        break;
                    case WARN:
                        logger.warn(format, arg);
                        break;
                    case ERROR:
                        logger.error(format, arg);
                        break;
                }
            }
        }

        private static void log(Level level, org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
            if (instance != null) {
                logToInstance(level, MessageFormatter.format(format, arg1, arg2));
            } else {
                switch (level) {
                    case TRACE:
                        logger.trace(format, arg1, arg2);
                        break;
                    case DEBUG:
                        logger.debug(format, arg1, arg2);
                        break;
                    case INFO:
                        logger.info(format, arg1, arg2);
                        break;
                    case WARN:
                        logger.warn(format, arg1, arg2);
                        break;
                    case ERROR:
                        logger.error(format, arg1, arg2);
                        break;
                }
            }
        }

        private static void log(Level level, org.slf4j.Logger logger, String format, Object... args) {
            if (instance != null) {
                logToInstance(level, MessageFormatter.arrayFormat(format, args));
            } else {
                switch (level) {
                    case TRACE:
                        logger.trace(format, args);
                        break;
                    case DEBUG:
                        logger.debug(format, args);
                        break;
                    case INFO:
                        logger.info(format, args);
                        break;
                    case WARN:
                        logger.warn(format, args);
                        break;
                    case ERROR:
                        logger.error(format, args);
                        break;
                }
            }
        }

        private static void logToInstance(Level level, FormattingTuple formattingTuple) {
            if (instance != null) {

                Throwable throwable = formattingTuple.getThrowable();
                String message = formattingTuple.getMessage();

                if (Level.ERROR == level) {
                    if (throwable != null) {
                        instance.logError(message, throwable);
                    } else {
                        instance.logError(message, new Throwable("Throwable missing in logger.error"));
                    }
                } else {
                    if (throwable != null) {
                        instance.logDebug(message + " Throwable: " + throwable.getMessage());
                    } else {
                        instance.logDebug(message);
                    }
                }
            }
        }


    }

    /**
     * Specifies how debug messages are logged.
     * <p>
     * If this method is not overridden, then debug messages will not be logged.
     *
     * @param message the message can to be logged
     */
    protected void logDebug(String message) {
    }

    /**
     * Specifies how error messages (with exceptions) are logged.
     * <p>
     * If this method is not overridden, then error messages will not be logged.
     *
     * @param message   the message can to be logged
     * @param throwable the exception that can to be logged or counted
     */
    protected void logError(String message, Throwable throwable) {
    }

    @Nullable
    static Logger instance = null;

    /**
     * Set the Logger implementation to use. Override the logDebug and logError methods to produce
     * logs. Call with null to disable logging.
     *
     * @param logger the Logger implementation to use
     */
    public static void setLogger(@Nullable Logger logger) {
        instance = logger;
    }

    /**
     * Log a debug message.
     */
    public static void d(String message) {
        if (instance != null) {
            instance.logDebug(message);
        }
    }

    /**
     * Log an error message, together with an exception.
     */
    public static void e(String message, Throwable throwable) {
        if (instance != null) {
            instance.logError(message, throwable);
        }
    }

    public static void trace(org.slf4j.Logger logger, String message) {
        Internal.log(Level.TRACE, logger, message);
    }

    public static void trace(org.slf4j.Logger logger, String format, Object arg) {
        Internal.log(Level.TRACE, logger, format, arg);
    }

    public static void trace(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
        Internal.log(Level.TRACE, logger, format, arg1, arg2);
    }

    public static void trace(org.slf4j.Logger logger, String format, Object... args) {
        Internal.log(Level.TRACE, logger, format, args);
    }

    public static void debug(org.slf4j.Logger logger, String message) {
        Internal.log(Level.DEBUG, logger, message);
    }

    public static void debug(org.slf4j.Logger logger, String format, Object arg) {
        Internal.log(Level.DEBUG, logger, format, arg);
    }

    public static void debug(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
        Internal.log(Level.DEBUG, logger, format, arg1, arg2);
    }

    public static void debug(org.slf4j.Logger logger, String format, Object... args) {
        Internal.log(Level.DEBUG, logger, format, args);
    }

    public static void info(org.slf4j.Logger logger, String message) {
        Internal.log(Level.INFO, logger, message);
    }

    public static void info(org.slf4j.Logger logger, String format, Object arg) {
        Internal.log(Level.INFO, logger, format, arg);
    }

    public static void info(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
        Internal.log(Level.INFO, logger, format, arg1, arg2);
    }

    public static void info(org.slf4j.Logger logger, String format, Object... args) {
        Internal.log(Level.INFO, logger, format, args);
    }

    public static void warn(org.slf4j.Logger logger, String message) {
        Internal.log(Level.WARN, logger, message);
    }

    public static void warn(org.slf4j.Logger logger, String format, Object arg) {
        Internal.log(Level.WARN, logger, format, arg);
    }

    public static void warn(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
        Internal.log(Level.WARN, logger, format, arg1, arg2);
    }

    public static void warn(org.slf4j.Logger logger, String format, Object... args) {
        Internal.log(Level.WARN, logger, format, args);
    }

    public static void error(org.slf4j.Logger logger, String message) {
        Internal.log(Level.ERROR, logger, message);
    }

    public static void error(org.slf4j.Logger logger, String format, Object arg) {
        Internal.log(Level.ERROR, logger, format, arg);
    }

    public static void error(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
        Internal.log(Level.ERROR, logger, format, arg1, arg2);
    }

    public static void error(org.slf4j.Logger logger, String format, Object... args) {
        Internal.log(Level.ERROR, logger, format, args);
    }
}
