# OTP Module
The **OTP** module provides classes and resources to accelerate Yubico OTP authentication integrations. The **OTP** module can:
* Detect whether a YubiKey is connected over NFC or USB
* Show a UI Dialog to request the user to take action to produce a Yubico OTP
* Parse a Yubico OTP

This module is intended to be used with a Yubico OTP validation server, such as the [YubiCloud service](https://www.yubico.com/products/services-software/yubicloud/). To learn more about the Yubico OTP authentication mechanism, go to [OTPs Explained](https://developers.yubico.com/OTP/OTPs_Explained.html) on Developers.Yubico.com.

The **OTP** module requires at minimum Java 7 or Android 4.4. Versions earlier than Android 8.0 may have been tested to a lesser extent.

## Integrating OTP Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {  
  // core library, connection detection, and raw APDU commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // OTP
  implementation 'com.yubico.yubikit:otp:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=1.0.0-beta05
```
#### Maven
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta05</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>otp</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```
### Using OTP Library <a name="using_lib"></a>

1. Launch the dialog that obtains the Yubico OTP from the NFC or USB device:
```java
    startActivityForResult(new Intent(context, OtpActivity.class), OTP_REQUEST_CODE)
```

2. Check the results from that `OtpActivity`:
```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == OTP_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK && data != null) {
                String otp = data.getStringExtra(OtpActivity.EXTRA_OTP);
                // do validation
            } else if (requestCode != Activity.RESULT_CANCELED && data != null) {
                Throwable error = (Throwable)data.getSerializableExtra(OtpActivity.EXTRA_ERROR);
                // show error to user
            }
        }
    }
```

**Note**: You can create a custom dialog to meet your UX requirements. Review the implementation of the `OtpActivity` class and detect the NFC tag or USB connection using **YubiKit** core methods.

### Using Demo Application <a name="using_demo"></a>
1. Run the [demo app](../YubikitDemo).
2. Select "OTP demo" in the navigation drawer.
3. Click the "Read OTP" button and follow the instructions on screen.
4. Validate the Yubico OTP obtained by clicking the "Validate OTP" button.
