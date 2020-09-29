package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;

import java.util.Arrays;

/**
 * Configures the YubiKey to output a Static Ticket.
 * NOTE: {@link StaticPasswordSlotConfiguration} is a better choice in most cases!
 * <p>
 * A Static Ticket behaves like a Yubico OTP, but with all changing state removed.
 */
public class StaticTicketSlotConfiguration extends KeyboardSlotConfiguration<StaticTicketSlotConfiguration> {
    /**
     * Creates a Static Ticket configuration with default settings.
     *
     * @param fixed data to use for the fixed portion of the ticket
     * @param uid   uid value (corresponds to a Yubico OTP private ID)
     * @param key   AES key used to generate the "dynamic" part of the ticket
     */
    public StaticTicketSlotConfiguration(byte[] fixed, byte[] uid, byte[] key) {
        super(new Version(1, 0, 0));
        if (fixed.length > ConfigUtils.FIXED_SIZE) {
            throw new IllegalArgumentException("Public ID must be <= 16 bytes");
        }

        this.fixed = Arrays.copyOf(fixed, fixed.length);
        System.arraycopy(uid, 0, this.uid, 0, uid.length);
        System.arraycopy(key, 0, this.key, 0, key.length);

        updateCfgFlags(CFGFLAG_STATIC_TICKET, true);
    }

    @Override
    protected StaticTicketSlotConfiguration getThis() {
        return this;
    }

    /**
     * Truncate the OTP-portion of the ticket to 16 characters.
     *
     * @param shortTicket if true, the OTP is truncated to 16 characters (default: false)
     * @return the configuration for chaining
     */
    public StaticTicketSlotConfiguration shortTicket(boolean shortTicket) {
        return updateTktFlags(CFGFLAG_SHORT_TICKET, shortTicket);
    }

    /**
     * Modifier flags to alter the output string to conform to password validation rules.
     * <p>
     * NOTE: special=true implies digits=true, and cannot be used without it.
     *
     * @param upperCase if true the two first letters of the output string are upper-cased (default: false)
     * @param digit     if true the first eight characters of the modhex alphabet are replaced with the numbers 0 to 7 (default: false)
     * @param special   if true a ! is sent as the very first character, and digits is implied (default: false)
     * @return the configuration for chaining
     */
    public StaticTicketSlotConfiguration strongPassword(boolean upperCase, boolean digit, boolean special) {
        updateCfgFlags(CFGFLAG_STRONG_PW1, upperCase);
        updateCfgFlags(CFGFLAG_STRONG_PW2, digit || special);
        return updateCfgFlags(CFGFLAG_SEND_REF, special);
    }

    /**
     * Enabled Manual Update of the static ticket.
     * NOTE: This feature is ONLY supported on YubiKey 2.x
     * <p>
     * Manual update is triggered by the user by holding the sensor pressed for 8-15 seconds.
     * This will generate a new random static ticket to be used, until manual update is again invoked.
     *
     * @param manualUpdate if true, enable user-initiated manual update (default: false)
     * @return the configuration for chaining
     */
    public StaticTicketSlotConfiguration manualUpdate(boolean manualUpdate) {
        return updateCfgFlags(CFGFLAG_MAN_UPDATE, manualUpdate);
    }
}
