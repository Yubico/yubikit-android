package com.yubico.yubikit.transport.nfc;

/**
 * Additional configurations for NFC discovery
 */
public class NfcConfiguration {

    // system sound that emitted when tag is discovered
    private boolean disableNfcDiscoverySound = false;

    // skip ndef check for discovered tag
    private boolean skipNdefCheck = false;

    // show settings dialog in case if NFC setting is not enabled
    private boolean handleUnavailableNfc = false;


    boolean isDisableNfcDiscoverySound() {
        return disableNfcDiscoverySound;
    }

    boolean isSkipNdefCheck() {
        return skipNdefCheck;
    }

    boolean isHandleUnavailableNfc() {
        return handleUnavailableNfc;
    }

    /**
     * Setting this flag allows the caller to prevent the
     * platform from playing sounds when it discovers a tag.
     * @param disableNfcDiscoverySound new value of this property
     * @return configuration object
     */
    public NfcConfiguration setDisableNfcDiscoverySound(boolean disableNfcDiscoverySound) {
        this.disableNfcDiscoverySound = disableNfcDiscoverySound;
        return this;
    }

    /**
     * Setting this flag allows the caller to prevent the
     * platform from performing an NDEF check on the tags it
     * @param skipNdefCheck new value of this property
     * @return configuration object
     */
    public NfcConfiguration setSkipNdefCheck(boolean skipNdefCheck) {
        this.skipNdefCheck = skipNdefCheck;
        return this;
    }

    /**
     * Set it to true to shows view with settings nfc setting if NFC is disabled,
     * otherwise start of NFC session will return error in callback if no permissions/setting
     * and allows user to handle disabled NFC reader (show error or snackbar or refer to settings)
     * Default value is false
     * @param handleUnavailableNfc new value of this property
     * @return configuration object
     */
    public NfcConfiguration setHandleUnavailableNfc(boolean handleUnavailableNfc) {
        this.handleUnavailableNfc = handleUnavailableNfc;
        return this;
    }

}
