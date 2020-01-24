# YubiKit for Android
**This is a pre-release version of YubiKit. Some of the specs and APIs may change in future releases so use this documentation and the library for prototyping and not for a public release. If you are an early adopter please provide detailed feedback about the design and issues you may find when using YubiKit.**

**YubiKit**  is an Android library provided Yubico to interact with YubiKeys. The library supports NFC-enabled and USB YubiKeys.

Please note, **YubiKit** consumes data from the token and translates to the application for further processing. **YubiKit** performs data validation for the purposes of creating valid responses to the application, however content/logical validation and security decisions are outside the scope of the **YubiKit** and must be handled by the application.

**YubiKit** is multi-module library with following components:

[Yubikit](./yubikit/README.md) provides an functionality to detect YubiKey plugged in or tapped over NFC, 

[OATH](./oath/README.md) allows applications, such as an authenticator app, to store OATH TOTP and HOTP secrets on a YubiKey, and to retrieve one-time passwords,

[OTP](./otp/README.md) provides classes to obtain Yubikey OTP

[FIDO2](./fido/README.md) supports a subset of FIDO2

[PIV](./piv/README.md) provides implementation of Personal Identity Verification (PIV) 

[MGMT](./mgmt/README.md) provides subset of API for personal customization of YubiKey and HMAC-SHA1 challenge-response

All **YubiKit** modules has javadoc and sources deployed with the library archive. Use this documentation for a more detailed explanation of all the methods, properties and parameters from the API.

This library comes with a demo application named **YubikitDemo**. The application is implemented in Kotlin.

## FAQ <a name="faq"></a>

#### Q1. Are there any versions of Android where YubiKit does not work?

YubiKit for FIDO2 should work on Android API 24+
Other YubiKit modules should work on Android API 19+
Yubico typically tests and support n-1 per https://en.wikipedia.org/wiki/Android_version_history.

#### Q2. How can I debug my app on Android when a YubiKey takes up the USB port?

You can set up adb debugging over WiFi: https://developer.android.com/studio/command-line/adb#wireless

## Additional resources <a name="additional_resources"></a>
1. Yubico - [Developers website](https://developers.yubico.com)
2. Yubico - [Online Demo](https://demo.yubico.com) 
![]()
