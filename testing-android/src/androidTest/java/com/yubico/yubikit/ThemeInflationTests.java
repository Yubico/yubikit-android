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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.util.TypedValue;
import androidx.core.content.ContextCompat;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.yubico.yubikit.testing.R;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Launches {@link TestActivity} and asserts its layout and theme resolve, without needing a
 * YubiKey. Guards the switch from Theme.MaterialComponents to Theme.AppCompat: an attribute that
 * stops resolving surfaces only at runtime, and every other instrumented test blocks waiting for a
 * key before it would ever notice.
 *
 * <p>Deliberately does not require the RESUMED state. Inflation and theme resolution both complete
 * in {@code onCreate}, while RESUMED is unreachable on a locked or dozing device - the normal
 * condition for an unattended run with the phone left sitting on a key.
 */
@RunWith(AndroidJUnit4.class)
public class ThemeInflationTests {

  @Test
  public void activityInflatesUnderAppCompatTheme() {
    try (ActivityScenario<TestActivity> scenario = ActivityScenario.launch(TestActivity.class)) {
      scenario.onActivity(
          activity -> {
            assertNotNull("statusText did not inflate", activity.findViewById(R.id.statusText));
            assertNotNull("progressBar did not inflate", activity.findViewById(R.id.progressBar));
            assertNotNull("bottomText did not inflate", activity.findViewById(R.id.bottomText));
          });
    }
  }

  @Test
  public void themeSuppliesYubicoColors() {
    try (ActivityScenario<TestActivity> scenario = ActivityScenario.launch(TestActivity.class)) {
      scenario.onActivity(
          activity -> {
            assertEquals(
                "colorPrimary is not yubico_green",
                ContextCompat.getColor(activity, R.color.yubico_green),
                resolveThemeColor(activity, androidx.appcompat.R.attr.colorPrimary));
            assertEquals(
                "colorAccent is not accent",
                ContextCompat.getColor(activity, R.color.accent),
                resolveThemeColor(activity, androidx.appcompat.R.attr.colorAccent));
          });
    }
  }

  private static int resolveThemeColor(TestActivity activity, int attr) {
    TypedValue value = new TypedValue();
    assertTrue(
        "theme attribute "
            + activity.getResources().getResourceEntryName(attr)
            + " does not resolve",
        activity.getTheme().resolveAttribute(attr, value, true));
    return value.data;
  }
}
