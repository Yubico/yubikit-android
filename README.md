# Yubico Mobile Android SDK (YubiKit)

**YubiKit** is an Android library provided by Yubico to enable interaction between YubiKeys and Android devices. The library supports NFC-enabled and USB YubiKeys.

The library includes a demo application implemented in Kotlin, the [YubiKit Demo App](./YubikitDemo), which provides a complete example of integrating and using all the features of the library in an Android project.

Changes to this library are documented in the [Changelog](./Changelog.md).

**NOTE** The pre-release version of YubiKit Android SDK supported a subset of FIDO2 functionality. In this general availability (GA) version, that FIDO2 module has been removed. If you require the FIDO2 module, we recommend developers use the official [FIDO2 API for Android](https://developers.google.com/identity/fido/android/native-apps) provided by Google.


## About

YubiKit requires a physical key to test its features. Running the included [demo application](./YubikitDemo/README.md) and integrating YubiKit into your app requires a YubiKey in order to test functionality.

YubiKit is a multi-module library with the following components:

[YubiKit](./yubikit/README.md) provides functionality for detecting whether a YubiKey is plugged into a device or connected to a device over NFC.

[OATH](./oath/README.md) provides functionality to store OATH TOTP and HOTP credentials and obtain one-time codes.

[OTP](./otp/README.md) provides implementation classes to obtain Yubico OTPs using either USB or NFC.

[PIV](./piv/README.md) provides an implementation of the Personal Identity Verification (PIV) interface.

[MGMT](./mgmt/README.md) provides YubiKey management functionality. This includes a subset of the API for personal customization of the YubiKey and the HMAC-SHA1 challenge-response.

All YubiKit modules include javadoc and additional resources deployed with the library archive. Refer to the javadoc documentation detailed about the API's methods, properties, and parameters.


**NOTE** YubiKit consumes data from the token and translates it to the application for further processing. YubiKit performs data validation for the purposes of creating valid responses to the application. Neither content validation nor logical validation are included in YubiKit, and nor are security decisions. These tasks must be handled by your application.


## Getting Started

To get started:

1. Download the zip file containing all the required library assets.
2. Try the [YubiKit Demo App](./YubikitDemo). This is included with the library.
3. Start integrating the library into your own application.

### Try the Demo

Use the [YubiKit Demo App](./YubikitDemo) to learn how to integrate YubiKit for Android with your app. The Demo app shows several examples of how to use YubiKit. It shows how the library is linked with a project so it can be used for a side-by-side comparison when adding the library to your own project.

Open the YubiKitDemo Android Studio project and run it on a real device or an emulator to see the features.

### Integrating and Using the Library

YubiKit SDK is available as a multi-module library. Add each module as a dependency to your Android project. Each module has a README that provides the instructions for integrating and using that module. See the *About* section above for a list of the modules with links to their associated READMEs.

### Support

If you run into any issues during the development process, please fill out a developer [support ticket](https://support.yubico.com/support/tickets/new) and our team will be happy to assist you.



## FAQ <a name="faq"></a>

### Q1. Does YubiKit work with all versions of Android?

A1. All YubiKit modules should work on Android API 19+. Yubico typically tests and supports n-1 per https://en.wikipedia.org/wiki/Android_version_history.

### Q2. How can I debug my app on Android when a YubiKey takes up the USB port?

A2. Set up Android Debug Bridge (adb) debugging over WiFi: https://developer.android.com/studio/command-line/adb#wireless

### Q3.  Why is the USB device permissions prompt shown every time the YubiKey is connected?

A3. This is an Android limitation. Android handles these permissions at the OS level. The only workaround is to use an intent filter, as described in the Android Developers Guide [USB Host Overview](https://developer.android.com/guide/topics/connectivity/usb/host.html#using-intents). However, if you apply this filter to remove the permissions prompt, then you cannot prevent your app from launching automatically whenever the YubiKey is connected.

### Q4. Why does the Android YubiKit library not provide a FIDO2 module?

A4. The current state of the Google FIDO2 API provided by Google Play Services is so much improved that Yubico adding a wrapper would not have accomplished anything significant. We recommend developers use the [official FIDO2 APIs provided by Google](https://developers.google.com/identity/fido/android/native-apps).

### Q5. Does the YubiKit support both USB and NFC?

A5. Yes. The core library, the **YubiKit** module [YubiKit README](/yubikit/README.md), provides the functionality to detect the plugged-in YubiKey (USB) or YubiKey NFC sufficiently close to the NFC reader and opens an ISO/IEC 7816 connection to send raw APDU commands to the YubiKey.


## Additional Resources

* Yubico - [developers.yubico.com](https://developers.yubico.com)
* Yubico - [Online Demo](https://demo.yubico.com) for YubiOTP, OATH, and WebAuthn
* Yubico - [OTP documentation](https://developers.yubico.com/OTP)
* Yubico - [What is U2F?](https://developers.yubico.com/U2F)
* Yubico - [YKOATH Protocol Specifications](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
* FIDO Alliance - [CTAP2 specifications](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
* W3.org - [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn/)
* Android Developers site - [developer.android.com](https://developer.android.com)
