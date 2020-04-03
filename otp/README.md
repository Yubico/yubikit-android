# OTP Module for YubiKit Android
**OTP** is module of Android YubiKit library provided Yubico that provides classes to parse Yubikey OTP from NFC tag, UI dialog to show user that OTP reading requires his action and detecting OTP from device connected over NFC or USB.
About Yubico OTP and advantages of using it please read on [Yubico developers website](https://developers.yubico.com/OTP/OTPs_Explained.html)

**OTP** module requires at minimum  Java 7 or Android 4.4, future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
###Download
####Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // OTP
  implementation 'com.yubico.yubikit:otp:$yubikitVersion'
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
  <artifactId>otp</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```
###Using Library <a name="using_lib"></a>

1. Launch dialog that obtains YK OTP from NFC or USB device
```java
    startActivityForResult(new Intent(context, OtpActivity.class), OTP_REQUEST_CODE)
```

2. Check results from that OtpActivity
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

If this dialog does not meet your requirements you can check implementation of OtpActivity class and implement it using **YubiKit** core methods to detect NFC tag or USB connection.

### Using the Demo Application <a name="using_demo"></a>
Run demo app, select "OTP demo" pivot in navigation drawer, tap "Read OTP" button and follow instructions on screen.
To validate retrieved OTP tap on "Validate OTP" button 
