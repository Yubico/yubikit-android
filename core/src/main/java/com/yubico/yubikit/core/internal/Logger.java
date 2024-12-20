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

package com.yubico.yubikit.core.internal;

import javax.annotation.Nullable;
import org.slf4j.event.Level;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MessageFormatter;

/** Used internally in YubiKit, don't use from applications. */
@SuppressWarnings({"unused", "deprecation"})
public final class Logger {

  @Nullable private static com.yubico.yubikit.core.Logger instance = null;

  public static void setLogger(@Nullable com.yubico.yubikit.core.Logger logger) {
    instance = logger;
  }

  public static void trace(org.slf4j.Logger logger, String message) {
    log(Level.TRACE, logger, message);
  }

  public static void trace(org.slf4j.Logger logger, String format, Object arg) {
    log(Level.TRACE, logger, format, arg);
  }

  public static void trace(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
    log(Level.TRACE, logger, format, arg1, arg2);
  }

  public static void trace(org.slf4j.Logger logger, String format, Object... args) {
    log(Level.TRACE, logger, format, args);
  }

  public static void debug(org.slf4j.Logger logger, String message) {
    log(Level.DEBUG, logger, message);
  }

  public static void debug(org.slf4j.Logger logger, String format, Object arg) {
    log(Level.DEBUG, logger, format, arg);
  }

  public static void debug(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
    log(Level.DEBUG, logger, format, arg1, arg2);
  }

  public static void debug(org.slf4j.Logger logger, String format, Object... args) {
    log(Level.DEBUG, logger, format, args);
  }

  public static void info(org.slf4j.Logger logger, String message) {
    log(Level.INFO, logger, message);
  }

  public static void info(org.slf4j.Logger logger, String format, Object arg) {
    log(Level.INFO, logger, format, arg);
  }

  public static void info(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
    log(Level.INFO, logger, format, arg1, arg2);
  }

  public static void info(org.slf4j.Logger logger, String format, Object... args) {
    log(Level.INFO, logger, format, args);
  }

  public static void warn(org.slf4j.Logger logger, String message) {
    log(Level.WARN, logger, message);
  }

  public static void warn(org.slf4j.Logger logger, String format, Object arg) {
    log(Level.WARN, logger, format, arg);
  }

  public static void warn(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
    log(Level.WARN, logger, format, arg1, arg2);
  }

  public static void warn(org.slf4j.Logger logger, String format, Object... args) {
    log(Level.WARN, logger, format, args);
  }

  public static void error(org.slf4j.Logger logger, String message) {
    log(Level.ERROR, logger, message);
  }

  public static void error(org.slf4j.Logger logger, String format, Object arg) {
    Logger.log(Level.ERROR, logger, format, arg);
  }

  public static void error(org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
    Logger.log(Level.ERROR, logger, format, arg1, arg2);
  }

  public static void error(org.slf4j.Logger logger, String format, Object... args) {
    Logger.log(Level.ERROR, logger, format, args);
  }

  private static void log(Level level, org.slf4j.Logger logger, String message) {
    if (instance != null) {
      if (Level.ERROR == level) {
        com.yubico.yubikit.core.Logger.e(
            message, new Exception("Throwable missing in logger.error"));
      } else {
        com.yubico.yubikit.core.Logger.d(message);
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

  private static void log(
      Level level, org.slf4j.Logger logger, String format, Object arg1, Object arg2) {
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
          com.yubico.yubikit.core.Logger.e(message, throwable);
        } else {
          com.yubico.yubikit.core.Logger.e(
              message, new Throwable("Throwable missing in logger.error"));
        }
      } else {
        if (throwable != null) {
          com.yubico.yubikit.core.Logger.d(message + " Throwable: " + throwable.getMessage());
        } else {
          com.yubico.yubikit.core.Logger.d(message);
        }
      }
    }
  }
}
