# MGMT Module
The **MGMT** module provides YubiKey management functionality, such as:
* Enable or disable applets and transports
* Personalization of YubiKey, e.g. programming OTP slots
* An API to utilize the HMAC-SHA1 challenge-response feature of the YubiKey

The **MGMT** module requires at minimum Java 7 or Android 4.4. Future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
### Download
#### Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // mgmt
  implementation 'com.yubico.yubikit:mgmt:$yubikitVersion'
}
```
And in `gradle.properties` set latest version. Example:
```gradle
yubikitVersion=1.0.0-beta05
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta05</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>mgmt</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```
### Using Library <a name="using_lib"></a>

The **MGMT** module requires the yubikit core library to detect a `YubikeySession` (see [Using YubiKit](../yubikit/README.md)). Use the session to create a `ManagementApplication` to select the MGMT applet. Additionally, use the session to create a  `YubiKeyConfigurationApplication` to customize/personalize the OTP slots or challenge-response.

```java

    ManagementApplication application = new ManagementApplication(session);
    // run provided command/operation (readConfiguration/writeConfiguration)
    
    
    // HMAC-SHA1 challenge-response
    YubiKeyConfigurationApplication application = new YubiKeyConfigurationApplication(session);
    byte[] response = application.calculateHmacSha1(challenge, Slot.TWO);
    
```

### Using the Demo Application <a name="using_demo"></a>
This module provides multiple demos.

#### Management functionality
1. Select "YubiKey Settings" pivot in navigation drawer
1. Turn off/on YubiKey applets and transports (YubiKey Series 5+ required)
   Note: Use this demo to emulate various YubiKey configurations, e.g. disable the NFC transport to emulate a USB only YubiKey. Verify your application behaves as expected with the various YubiKey configurations.

#### Programming OTP slots
Things to consider before running this demo: 
* By default the slot ONE is programmed with YubiOTP secret. Overriding first slot means loosing this secret.
* YubiOTP codes that were generated on key can be read using "Yubico OTP demo" pivot. Refer to the [OTP module](../otp/README.md) to learn more.
* The recommendation for programming HOTP secrets is to use the [OATH module](../oath/README.md) and an Authenticator application. This method allows the storage of multiple HOTP secrets. The Authenticator app can then calculate them whenever needed.

To program an OTP slot:
1. Select the "Configure OTP" pivot. 
1. Select one of the four types of customization: YubiOTP, static Password, secret for HMAC-SHA1 challenge-response, or HOTP secret 
