# Yubico Mobile Android SDK (YubiKit)

**YubiKit** is an Android library provided by Yubico to interact with YubiKeys on Android devices. The library supports NFC-enabled and USB YubiKeys.

The library includes a demo application implemented in Kotlin, the [YubiKit Demo App](./yubikit-android/tree/master/YubikitDemo), which provides a complete example of integrating and using all the features of the library in an Android project.

Changes to this library are documented in this [changelog](./yubikit-android/blob/master/Changelog.md).

**NOTE** The pre-release version of YubiKit Android SDK supported a subset of FIDO2 functionality. In this general availability (GA) version, that FIDO2 module has been removed. We recommend developers use the official [FIDO2 API for Android](https://developers.google.com/identity/fido/android/native-apps) provided by Google.


## About

YubiKit requires a physical key to test its features. In order to run the included [demo application](./yubikit-android/tree/master/YubikitDemo) and to integrate the YubiKit into your own app, get a YubiKey or a Security Key by Yubico to test functionality.

YubiKit is a multi-module library with the following components:

[Yubikit](./yubikit/README.md) provides functionality to detect whether a YubiKey is plugged in or connected over NFC.

[OATH](./oath/README.md) enables applications such as an authenticator app to store OATH TOTP and HOTP secrets on a YubiKey and generate one-time passwords.

[OTP](./otp/README.md) provides implementation classes to obtain Yubico OTPs via USB or NFC.

[PIV](./piv/README.md) provides an implementation of the Personal Identity Verification (PIV) interface.

[MGMT](./management/README.md) provides YubiKey management functionality, a subset of the API for personal customization of the YubiKey and the HMAC-SHA1 challenge-response.

All YubiKit modules have javadoc and sources deployed with the library archive. Use that documentation for a more detailed explanation of all the APIs methods, properties and parameters.


### Note

YubiKit consumes data from the token and translates it to the application for further processing. YubiKit performs data validation for the purposes of creating valid responses to the application; however, content/logical validation and security decisions are outside YubiKit's scope and must therefore be handled by the application.


## Getting Started

To get started, you can try the [YubiKit Demo App](./yubikit-android/tree/master/YubikitDemo) as part of this library or start integrating the library into your own application. Before starting to look at the SDK, make sure you have downloaded the zip file containing all the necessary assets for using the library.

### Try the Demo

Use the [YubiKit Demo App](./yubikit-android/tree/master/YubikitDemo) to learn how to integrate YubiKit for Android with your app. The Demo app shows several examples of how to use YubiKit, including WebAuthn/FIDO2 over the accessory or NFC YubiKeys. It shows how the library is linked with a project so it can be used for a side-by-side comparison when adding the library to your own project.

Open the YubiKitDemo Android Studio project and run it on a real device or an emulator to see the features.

### Integrating and Using the Library

YubiKit SDK is available as a multi-module library to be added as a dependency to your Android project. The instructions for integrating and using each module are in the README for each of the modules listed above in the About section, which also provides a link to each README.


## FAQ <a name="faq"></a>

### Q1. Does YubiKit work with all versions of Android?

A1. All YubiKit modules should work on Android API 19+. Yubico typically tests and supports n-1 per https://en.wikipedia.org/wiki/Android_version_history.

### Q2. How can I debug my app on Android when a YubiKey takes up the USB port?

A2. You can set up Android Debug Bridge (adb) debugging over WiFi: https://developer.android.com/studio/command-line/adb#wireless

### Q3.  Why is the USB device permissions prompt being shown every time the YubiKey is connected?

A3. This is an Android limitation. Android deals with these permissions at the OS level, and the only workaround is to use an intent filter as described in the Android Developers Guide [USB Host Overview](https://developer.android.com/guide/topics/connectivity/usb/host.html#using-intents). However, while this gets rid of the permissions prompt, it also causes your app to launch automatically whenever the YubiKey is connected.


## Additional Resources

* Yubico - [Developers' website](https://developers.yubico.com)
* Yubico - [Online Demo](https://demo.yubico.com) for OTP and U2F
* Yubico - [OTP documentation](https://developers.yubico.com/OTP)
* Yubico - [What is U2F?](https://developers.yubico.com/U2F)
* Yubico - [YKOATH Protocol Specifications](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
* FIDO Alliance - [CTAP2 specifications](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
* W3.org - [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn/)
* Android Developers site - [developer.android.com](https://developer.android.com)
