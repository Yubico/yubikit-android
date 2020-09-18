# OATH Module
The **oath** module enables applications such as an authenticator app to store
OATH TOTP and HOTP secrets on a YubiKey, and to retrieve OTPs.

## Integrating OATH Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {
  implementation 'com.yubico.yubikit:android:$yubikitVersion'
  implementation 'com.yubico.yubikit:oath:$yubikitVersion'
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
  <artifactId>oath</artifactId>
  <version>2.0.0</version>
</dependency>
```

### Using OATH Library <a name="using_lib"></a>
The **OATH** module requires the YubiKit android module to detect a
`YubikeyDevice` (see [Android Module README](../android/README.md)).

First, create an `OathSession` to select the OATH applet on the YubiKey.
```java

    OathSession session = new OathSession(device);
    // run provided command/operation (put/calculate/delete/etc)
    // example:
    //    try {
    //        session.putCredential(CredentialData.parseUri(uri));
    //    } catch (ParseUriException | IOException | ApduException e) {
    //        // handle errors
    //    }

```

Next, use the `OathSession` to add, remove, list, and calculate credentials.

The `OathSession` implements the YKOATH protocol. Refer to the [YKOATH protocol specification](https://developers.yubico.com/OATH/YKOATH_Protocol.html) for more details.

In addition, the `OathSession` provides an interface for setting/validating a password on credential storage, calculating all credentials, and resetting the OATH application to its default state. For the complete list of methods look at the [`OathSession` class documentation](src/main/java/com/yubico/yubikit/oath/OathSession.java).

The **OATH** module also provides a class for defining an OATH `CredentialData`. Use its factory method `CredentialData.parseUri` to parse the credential parameters from the Uri of the [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

### Using Demo Application <a name="using_demo"></a>
1. Run the [demo app](../YubikitDemo).
2. Select "OATH" in the navigation drawer.

## Additional Resources <a name="additional_resources"></a>
* [YKOATH Protocol Specification](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
