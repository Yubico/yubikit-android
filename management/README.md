# MGMT Module for YubiKit Android
**MGMT** is module of Android YubiKit library provided Yubico.
It provides management functionality of YubiKey which allows to enable or disable applets/transport

**MGMT** requires at minimum  Java 7 or Android 4.4, future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
###Download
####Gradle:

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
yubikitVersion=1.0.0-beta03
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta03</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>mgmt</artifactId>
  <version>1.0.0-beta03</version>
</dependency>
```
###Using Library <a name="using_lib"></a>

This module requires usage of yubikit core library to detect `YubikeySession` (see [Using YubiKit](../yubikit/README.md))  
And use it to create `ManagementApplication` to select MGMT applet on YubiKey  
```java

    ManagementApplication application = new ManagementApplication(session);
    // run provided command/operation (generateKey/putCertificate/sign/etc)
    
```

### Using the Demo Application <a name="using_demo"></a>
Run demo app, select "YubiKey Settings" pivot in navigation drawer. Plug in YubiKey or tap over NFC reader. And turn off/on some of yubikey service. 
You can also check using other demos how your application will behave if any of services is disabled.