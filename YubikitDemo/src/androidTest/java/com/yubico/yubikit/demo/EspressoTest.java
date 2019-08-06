package com.yubico.yubikit.demo;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.espresso.Espresso;
import androidx.test.espresso.IdlingRegistry;
import androidx.test.espresso.action.ViewActions;
import androidx.test.espresso.contrib.NavigationViewActions;
import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.rule.ActivityTestRule;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withSubstring;


@RunWith(AndroidJUnit4.class)
public class EspressoTest {

    @Rule
    public ActivityTestRule<MainActivity> activityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Test
    public void smartcarddemo_nfc() throws Exception {

        //wait for completion, or timeout in ElapsedTimeIdlingResource(X) where X is in milliseconds
        ElapsedTimeIdlingResource iresLogRead = new ElapsedTimeIdlingResource(3000);

        //navigate to Smartcard Demo
        onView(withId(R.id.nav_view))
                .perform(NavigationViewActions.navigateTo(R.id.smartcard_fragment));

        IdlingRegistry.getInstance().register(iresLogRead);

        //Test pass if "signature is valid" is shown; otherwise, test fails.
        onView(withId(R.id.log))
                .check(matches(withSubstring("Signature is valid")));

        IdlingRegistry.getInstance().unregister(iresLogRead);
    }
}