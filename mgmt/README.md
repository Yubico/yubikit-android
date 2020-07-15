# MGMT Module
The **MGMT** module provides YubiKey management functionality such as:
* Enabling or disabling applets and transports
* Personalization of YubiKey; for example, programming OTP slots
* An API to utilize the HMAC-SHA1 challenge-response feature of the YubiKey


## Requirements
The **MGMT** module requires at minimum Java 7 or Android 4.4. Versions earlier than Android 8.0 may have been tested to a lesser extent.


## Integrating MGMT Module <a name="integration_steps"></a>
### Downloading
#### Gradle

```gradle
dependencies {
  // core library, connection detection, and raw commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // mgmt
  implementation 'com.yubico.yubikit:mgmt:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=1.0.0
```

#### Maven
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>mgmt</artifactId>
  <version>1.0.0</version>
</dependency>
```
### Using MGMT Library <a name="using_lib"></a>

The **MGMT** module requires the YubiKit core library to detect a `YubikeySession` (see [YubiKit Module README](../yubikit/README.md)). Use the session to create:

a) a `ManagementApplication` to select the MGMT applet,

b) a `YubiKeyConfigurationApplication` to customize/personalize the OTP slots or challenge-response.

```java

    ManagementApplication application = new ManagementApplication(session);
    // run provided command/operation (readConfiguration/writeConfiguration)


    // HMAC-SHA1 challenge-response
    YubiKeyConfigurationApplication application = new YubiKeyConfigurationApplication(session);
    byte[] response = application.calculateHmacSha1(challenge, Slot.TWO);

```

### Using Demo Application <a name="using_demo"></a>
This module provides several demos.


#### Management Functionality
Requires YubiKey Series 5+. Use this demo to emulate various YubiKey configurations such as disabling the NFC transport to emulate a USB-only YubiKey. Verify your application behaves as expected with the various YubiKey configurations.

1. Select the *YubiKey Settings* in the navigation drawer.
2. Turn off/on YubiKey applets and transports


#### Programming OTP Slots
Before running this demo, be aware that:
* By default slot ONE is programmed with the YubiOTP secret. Overwriting this first slot will delete this secret.
* YubiOTP codes that were generated on the YubiKey can be read using the *Yubico OTP demo*. Refer to the [OTP Module](../otp/README.md) to learn more.
* The recommendation for programming HOTP secrets is to use the [OATH module](../oath/README.md) and an Authenticator application. This method allows the storage of multiple HOTP secrets. The Authenticator app can then calculate them whenever needed.

To program an OTP slot:

1. Select *Configure OTP*.
2. Select one of the four types of customization:

   * YubiOTP
   * Static Password
   * Secret for HMAC-SHA1 challenge-response
   * HOTP secret.
