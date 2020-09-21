# Management Module
The **management** module provides general YubiKey management functionality such as
enabling or disabling applications and transports.

## Integrating the Management Module <a name="integration_steps"></a>
### Downloading
#### Gradle

```gradle
dependencies {
  implementation 'com.yubico.yubikit:android:$yubikitVersion'
  implementation 'com.yubico.yubikit:management:$yubikitVersion'
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
  <artifactId>management</artifactId>
  <version>2.0.0</version>
</dependency>
```
### Using the Management Module <a name="using_lib"></a>
The **management** module requires the YubiKit android module to detect a
`YubikeyDevice` (see [Android Module README](../android/README.md)). Use the
device to create:

a) a `ManagementSession` to select the Management application,

```java
    ManagementSession application = ManagementSession.create(device);
    // run provided command/operation (getDeviceInfo/updateDeviceConfig)
```

### Using Demo Application <a name="using_demo"></a>
Requires YubiKey Series 5+. Use this demo to emulate various YubiKey configurations such as disabling the NFC transport to emulate a USB-only YubiKey. Verify your application behaves as expected with the various YubiKey configurations.

1. Select the *Device Configuration* in the navigation drawer.
2. Turn off/on YubiKey applets and transports
