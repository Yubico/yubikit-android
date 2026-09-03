/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import android.os.Bundle;
import android.util.Log;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;

/**
 * Verifies that SLF4J logging works on the device under test, without needing a YubiKey.
 *
 * <p>Every other instrumented test blocks in {@code TestActivity.awaitSession} until a key is
 * tapped, so none of them can run unattended - which is exactly where the low-API behaviour needs
 * checking. These tests touch no YubiKey and no activity.
 *
 * <p><b>The fluent tests are opt-in and will kill the test process on API &lt; 24.</b> See {@link
 * #requireFluentApiOptIn()}.
 *
 * <p>SLF4J-FLUENT-ALLOWED - exempt from the checkNoFluentSlf4j build check. Calling the fluent API
 * is the point of this file: it demonstrates that the calls still crash. Production code gets the
 * isXEnabled() guard instead, never this marker.
 */
@RunWith(AndroidJUnit4.class)
public class LoggingSmokeTests {

  private static final String TAG = "LoggingSmokeTests";

  /**
   * Instrumentation argument gating the fluent-API tests: {@code -e runFluentLoggingTests true}.
   */
  private static final String OPT_IN_ARG = "runFluentLoggingTests";

  /**
   * Skips unless the caller explicitly opted in.
   *
   * <p>On API 21 every fluent call - {@code logger.atDebug()} on its own is enough - dies with a
   * native SIGSEGV rather than a catchable exception, taking the whole instrumentation process with
   * it. A crashed process reports no results at all, so leaving these tests ungated would turn one
   * known bug into a silent, total loss of the run for every other test in the suite.
   *
   * <p>Cause: logback-android's prebuilt {@code ch.qos.logback.classic.Logger} implements none of
   * the SLF4J 2.x fluent methods. D8 emits the {@code org/slf4j/Logger$-CC} companion and leaves
   * the call site as {@code invoke-interface}, but injects no forwarder into the prebuilt class.
   * ART predates interface default methods before API 24, so dispatch lands on a bogus vtable slot.
   *
   * <p>The gate is an opt-in flag rather than an API-level check on purpose: an {@code SDK_INT >=
   * 24} guard would skip these tests precisely where they demonstrate the bug.
   */
  private static void requireFluentApiOptIn() {
    Bundle arguments = InstrumentationRegistry.getArguments();
    assumeTrue(
        "Fluent SLF4J tests crash the process on API < 24; pass -e "
            + OPT_IN_ARG
            + " true to run them",
        Boolean.parseBoolean(arguments.getString(OPT_IN_ARG)));
  }

  private static Logger logger() {
    Logger logger = LoggerFactory.getLogger(LoggingSmokeTests.class);
    Log.i(TAG, "SLF4J binding resolved to " + logger.getClass().getName());
    assertFalse(
        "SLF4J fell back to the no-op binding, so no log call reaches logcat",
        logger.getClass().getName().contains("NOPLogger"));
    return logger;
  }

  /** Plain logging, including the call shape used by {@code skipReasonLogger}. */
  @Test
  public void plainCalls() {
    Logger logger = logger();

    logger.error("SKIPPED {}: {}", "someTest", "some reason");
    logger.warn("warn {}", 1);
    logger.info("info {}", 2);
    logger.debug("debug {}", 3);
    logger.trace("trace {}", 4);

    Log.i(TAG, "plain logging OK");
  }

  /** The workaround shape: an isXEnabled() guard plus a plain call, no default methods. */
  @Test
  public void guardedPlainCalls() {
    Logger logger = logger();

    if (logger.isDebugEnabled()) {
      logger.debug("guarded debug {}", "value");
    }
    if (logger.isTraceEnabled()) {
      logger.trace("guarded trace {}", "value");
    }

    Log.i(TAG, "guarded logging OK");
  }

  /** Step 1 of the fluent chain: does the default method return a builder at all? */
  @Test
  public void fluentBuilderCreation() {
    requireFluentApiOptIn();
    Logger logger = logger();

    LoggingEventBuilder builder = logger.atDebug();
    Log.i(TAG, "atDebug() returned " + (builder == null ? "null" : builder.getClass().getName()));
    assertNotNull("atDebug() returned null", builder);

    Log.i(TAG, "fluent builder creation OK");
  }

  /** Step 2: configuring the builder, without terminating it. */
  @Test
  public void fluentBuilderConfiguration() {
    requireFluentApiOptIn();
    Logger logger = logger();

    LoggingEventBuilder builder = logger.atDebug().setMessage("configured {}").addArgument(7);
    Log.i(TAG, "configured builder is " + builder.getClass().getName());

    Log.i(TAG, "fluent builder configuration OK");
  }

  /** Step 3: the terminal log() call - the suspected failure point. */
  @Test
  public void fluentBuilderLog() {
    requireFluentApiOptIn();
    Logger logger = logger();

    logger.atDebug().setMessage("fluent debug {}").addArgument(8).log();

    Log.i(TAG, "fluent log() OK");
  }

  /** The single-argument terminal form, which takes a different path through the builder. */
  @Test
  public void fluentLogWithMessage() {
    requireFluentApiOptIn();
    Logger logger = logger();

    logger.atDebug().log("fluent debug, direct message");

    Log.i(TAG, "fluent log(String) OK");
  }

  /** The exact shape used by core: a lazily-evaluated Supplier argument. */
  @Test
  public void fluentWithSupplierArgument() {
    requireFluentApiOptIn();
    Logger logger = logger();

    logger.atDebug().setMessage("supplied: {}").addArgument(() -> "computed").log();

    Log.i(TAG, "fluent supplier OK");
  }
}
