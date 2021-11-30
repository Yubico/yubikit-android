package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;

import java.io.IOException;
import java.security.PublicKey;

final class JcaUtils {
    private JcaUtils() {}

    static PublicKey getPublicKey(PivSession session, Slot slot) throws IOException, ApduException {
        try {
            if (session.supports(PivSession.FEATURE_METADATA)) {
                return session.getSlotMetadata(slot).getPublicKey();
            } else {
                return session.getCertificate(slot).getPublicKey();
            }
        } catch (BadResponseException e) {
            throw new UnsupportedOperationException("Unable to read public key");
        }
    }
}
