# YubiKit Core Module
The **core** module is the base library, with common transports and utilities used
throughout the rest of the modules. This module is typically not used alone, but
as a dependency of the [android](../android/) module, and others.

## Integrating YubiKit Module <a name="integration_steps"></a>
### Downloading
#### Gradle
NOTE: You typically don't have to depend on this module explicitly, as it will
be pulled in as a dependency to other modules.

```gradle
dependencies {
  implementation 'com.yubico.yubikit:core:$yubikitVersion'
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
  <artifactId>core</artifactId>
  <version>2.0.0</version>
</dependency>
```

### Using the Demo Application <a name="using_demo"></a>
The library comes with a demo application, the [**YubiKitDemo**](../YubikitDemo).
This demo application showcases what this module can do as well as what the other
modules can do.
The source code for the demo application is provided as an example of library
usage.

## Additional Resources <a name="additional_resources"></a>
USB
- [Smart card CCID](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)

PIV
- [Interfaces for Personal Identity Verification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
- [Information and examples of what you can do with a PIV-enabled YubiKey](https://developers.yubico.com/PIV/)
