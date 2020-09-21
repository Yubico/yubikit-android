# YubiOTP Module
The **yubiotp** module provides an interface to configure the YubiKey OTP application,
which can be used to program a YubiKey slot with a Yubico OTP, OATH-HOTP,
HMAC-SHA1 Challenge-Response, or static password credential.

To learn more about the Yubico OTP authentication mechanism, go to [OTPs Explained](https://developers.yubico.com/OTP/OTPs_Explained.html) on Developers.Yubico.com.

## Integrating the YubiOTP Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {
  implementation 'com.yubico.yubikit:android:$yubikitVersion'
  implementation 'com.yubico.yubikit:yubiotp:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=2.0.0
```
#### Maven
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>android</artifactId>
  <version>2.0.0</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubiotp</artifactId>
  <version>2.0.0</version>
</dependency>
```
### Using the YubiOTP Library <a name="using_lib"></a>
The **YubiOTP** module requires the YubiKit android module to detect a
`YubikeySession` (see [Android Module README](../android/README.md)). Use the
device to create:

```java
    // HMAC-SHA1 challenge-response
    YubiOtpSession session = YubiOtpSession.create(device);
    byte[] response = session.calculateHmacSha1(Slot.TWO, challenge, null);
```

### Using Demo Application <a name="using_demo"></a>
NOTE: default slot ONE is programmed with a YubiCloud OTP secret. Overwriting
this first slot will delete this credential, which cannot be recovered!


1. Run the [demo app](../YubikitDemo).
2. Select "YubiOTP" in the navigation drawer.
3. Use the "Yubico OTP" tab to program and read a Yubico OTP
4. Use the "Challenge-response" tab to program a key and calculate a response.
