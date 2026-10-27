/*
 * Copyright (C) 2026 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.piv;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.yubico.yubikit.AlwaysManualTest;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import com.yubico.yubikit.framework.YkInstrumentedTests;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PIV exchanges over whatever smart card reader or YubiKey is attached, checked against the card:
 * reads, writes, key generation and signing, with every response verified rather than just
 * received. Meant to be run against a TPDU-level reader, an APDU-level reader and a YubiKey with
 * the same results, so it asserts nothing about the reader type; the host-framed T=1 flag is logged
 * by each test instead.
 *
 * <p>It speaks standard PIV (SP 800-73-4) with raw APDUs. A {@code PivSession} opens with
 * YubiKey-only commands and selects the application with the truncated AID that strict cards
 * refuse, so it cannot be used on a card that is not a YubiKey. Short APDUs are forced so every
 * reader carries exactly the same chunked commands, whatever the card does with extended length.
 *
 * <h2>What changes on the card</h2>
 *
 * <p>{@link #testReadCertificates} only reads, so it needs a certificate already on the card and
 * fails on one that has none, such as a freshly reset YubiKey. <b>Every other test destroys the key
 * and certificate in slot 9A</b>, generating a new key there or overwriting the certificate object,
 * and clears the certificate object again at the end. Use a card or YubiKey that can lose slot 9A.
 *
 * <h2>What it needs</h2>
 *
 * <ul>
 *   <li>The default management key: the pattern {@code 0102030405060708} repeated, 24 bytes for
 *       3DES or AES-192 and 32 bytes for AES-256. Each algorithm is offered in turn and a card
 *       without a key of that type refuses at the first request, which costs nothing. A card with
 *       another key fails after one rejected attempt and nothing is written.
 *   <li>PIN {@code 123456} for the signing tests. The retry counter is read first and the PIN is
 *       not tried unless at least {@value #MIN_PIN_RETRIES} retries remain, once per run; if the
 *       card refuses it, no later test tries it again.
 *   <li>A serial listed in {@code allowed_serials.csv} when the target is a YubiKey.
 * </ul>
 *
 * <h2>Running it</h2>
 *
 * <p>The class is in no suite, so neither {@code DeviceTests} nor {@code ExternalReaderTests} runs
 * it; name it explicitly:
 *
 * <pre>{@code
 * ./gradlew :testing-android:connectedDebugAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=com.yubico.yubikit.piv.PivRawApduReaderTests
 * }</pre>
 *
 * <p>Append {@code #testName} to run one test. With more than one phone on adb, set {@code
 * ANDROID_SERIAL} to pick the one with the hardware on it.
 *
 * <p><b>On a YubiKey</b>, plug it into the phone's USB-C port and make sure its serial is in {@code
 * allowed_serials.csv}. The key's own CCID interface is an APDU-level reader, so this is the
 * baseline the T=1 results are compared with. Each test logs {@code host-framed T=1: false}.
 *
 * <p><b>On a T=1 reader</b>, connect a TPDU-level contact reader to the phone over USB OTG, with a
 * PIV card in it. The reader occupies the phone's only USB-C port, so drive the run over wireless
 * adb. The card needs the default management key and PIN above and a slot 9A you can lose. A card
 * that is not a YubiKey is refused by the allow list unless the run opts in with {@code
 * -Pandroid.testInstrumentationRunnerArguments.allowExternalCards=true}; a YubiKey behind the
 * reader is never admitted that way. See the {@code testing-android} README. Each test logs {@code
 * host-framed T=1: true} when the SDK is framing T=1 itself; {@code UsbSmartCardConnection} also
 * logs the reader's {@code exchangeLevel=} at DEBUG, and a reader that advertises APDU level there
 * never reaches the T=1 code, whatever it is sold as. Cards that are not YubiKeys may refuse the
 * SDK's truncated PIV AID; this class selects the full one.
 *
 * <p>Long card operations are part of what this covers. Generating an RSA-2048 key takes the
 * SCR3500 C card several seconds, during which it keeps asking for more time with S(WTX) blocks, so
 * the run fails if the host stops waiting too early.
 */
public class PivRawApduReaderTests extends YkInstrumentedTests {

  private static final Logger logger = LoggerFactory.getLogger(PivRawApduReaderTests.class);

  /** The full PIV AID. The SDK's selector sends the truncated RID, which strict cards refuse. */
  private static final byte[] PIV_AID_FULL =
      new byte[] {
        (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
      };

  private static final int INS_GET_DATA = 0xCB;
  private static final int INS_PUT_DATA = 0xDB;
  private static final int INS_AUTHENTICATE = 0x87;
  private static final int SLOT_CARD_MANAGEMENT = 0x9B;

  /**
   * GENERAL AUTHENTICATE is a case 4 command: it carries data and expects data back. The formatter
   * only writes an Le byte when asked to, and some cards answer 6700 without one.
   */
  private static final int AUTHENTICATE_LE = 0xFF;

  private static final int INS_VERIFY = 0x20;
  private static final int PIN_REFERENCE = 0x80;
  private static final byte[] PIN = "123456".getBytes(StandardCharsets.US_ASCII);

  /** The PIN is only tried when at least this many retries remain, and only once per run. */
  private static final int MIN_PIN_RETRIES = 3;

  /** Set when the card refused the PIN, so no later test tries it again and burns a retry. */
  private static volatile boolean pinRejected = false;

  private static final byte ALG_RSA2048 = 0x07;

  private static final int INS_GENERATE_KEY = 0x47;
  private static final int SLOT_AUTHENTICATION = 0x9A;

  /** The data object that holds the certificate of slot 9A. */
  private static final int OBJECT_ID_9A = 0x5FC105;

  /** General Authenticate algorithm identifiers (SP 800-78-4 Table 6-2). */
  private static final int ALG_3DES = 0x03;

  private static final int ALG_AES192 = 0x0A;
  private static final int ALG_AES256 = 0x0C;

  /**
   * The default management key for a key of {@code length} bytes: {@code 0102030405060708}
   * repeated. At 24 bytes that is the YubiKey default for 3DES and AES-192; the 32-byte form is the
   * same pattern extended for AES-256.
   */
  private static byte[] defaultManagementKey(int length) {
    byte[] key = new byte[length];
    for (int i = 0; i < length; i++) {
      key[i] = (byte) (i % 8 + 1);
    }
    return key;
  }

  /** SW for "not enough memory", the one failure that only says the card is out of room. */
  private static final short SW_NOT_ENOUGH_MEMORY = 0x6A84;

  /**
   * Reads every certificate in the PIV slots and parses each as X.509. Read-only: no PIN or
   * management key is involved. A response that was chained over several blocks and reassembled
   * with a lost, duplicated or reordered block does not decode as a certificate, so a clean parse
   * is stronger evidence than a length check.
   */
  // GzipUtils is deprecated only for being public; it stays reachable from its own package.
  @SuppressWarnings("deprecation")
  @Test
  @Category(AlwaysManualTest.class)
  public void testReadCertificates() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openPiv(connection)) {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      int found = 0;
      for (Map.Entry<String, Integer> slot : certificateSlots().entrySet()) {
        byte[] response;
        try {
          response = protocol.sendAndReceive(getObject(slot.getValue()));
        } catch (ApduException e) {
          logger.info(
              "Slot {}: empty or not readable, SW=0x{}",
              slot.getKey(),
              String.format(Locale.ROOT, "%04x", e.getSw()));
          continue;
        }

        Map<Integer, byte[]> object = Tlvs.decodeMap(Tlvs.unpackValue(0x53, response));
        byte[] certificate = object.get(0x70);
        if (certificate == null || certificate.length == 0) {
          // An object that was cleared rather than never written answers 9000 with nothing in it.
          logger.info("Slot {}: object present but empty", slot.getKey());
          continue;
        }
        byte[] certInfo = object.get(0x71);
        if (certInfo != null && certInfo.length > 0 && certInfo[0] != 0) {
          certificate = GzipUtils.decompress(certificate);
        }

        X509Certificate parsed =
            (X509Certificate)
                certificateFactory.generateCertificate(new ByteArrayInputStream(certificate));
        logger.info(
            "Slot {}: {} bytes on the wire, subject={}, notAfter={}",
            slot.getKey(),
            response.length,
            parsed.getSubjectX500Principal().getName(),
            parsed.getNotAfter());
        found++;
      }

      assertTrue(
          "This test reads certificates already on the card, and none of its PIV certificate "
              + "slots holds one. Put a certificate on the card first; a freshly reset YubiKey "
              + "has none.",
          found > 0);
    }
  }

  /** The certificate slots and the data object each one is stored in, in slot order. */
  private static Map<String, Integer> certificateSlots() {
    Map<String, Integer> slots = new LinkedHashMap<>();
    slots.put("9A", 0x5FC105);
    slots.put("9C", 0x5FC10A);
    slots.put("9D", 0x5FC10B);
    slots.put("9E", 0x5FC101);
    for (int i = 0; i < 20; i++) {
      // Retired key management slots 82 to 95 (SP 800-73-4 Part 1, Table 3).
      slots.put(String.format(Locale.ROOT, "%02X", 0x82 + i), 0x5FC10D + i);
    }
    return slots;
  }

  /** Short APDUs and the full PIV AID selected, with no authentication. */
  private static SmartCardProtocol openPiv(SmartCardConnection connection) throws Throwable {
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    protocol.configure(
        new Version(5, 0, 0),
        new SmartCardProtocol.Configuration.Builder().setForceShortApdus(true).build());
    protocol.select(PIV_AID_FULL);
    return protocol;
  }

  /**
   * Generates a new ECC key in slot 9A, P-384 if the card has it and P-256 otherwise, stores a
   * certificate for it in the slot's data object and reads the certificate back. <b>This destroys
   * whatever key and certificate slot 9A held.</b>
   *
   * <p>The private key never leaves the card and using it would need the PIN, which this test does
   * not have and will not guess. The certificate is therefore signed by a throwaway software key
   * and the check is on the round trip instead: the certificate that comes back has to be identical
   * byte for byte, its signature has to verify, and the public key in it has to be the one the card
   * reported when it generated the pair. A certificate of this size spans several blocks in both
   * directions, so a lost, duplicated or reordered block fails the signature.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testGenerateKeyAndPutCertificateInSlot9A() throws Throwable {
    YubiKeyDevice currentDevice = device;
    assertNotNull("No device", currentDevice);

    try (SmartCardConnection connection = currentDevice.openConnection(SmartCardConnection.class);
        SmartCardProtocol protocol = new SmartCardProtocol(connection)) {
      logger.info(
          "Transport {}, host-framed T=1: {}",
          currentDevice.getTransport(),
          !connection.isExtendedLengthApduSupported());

      protocol.configure(
          new Version(5, 0, 0),
          new SmartCardProtocol.Configuration.Builder().setForceShortApdus(true).build());
      protocol.select(PIV_AID_FULL);
      authenticate(protocol);

      // GENERATE ASYMMETRIC KEY PAIR (SP 800-73-4 Part 2, §3.3.2) for slot 9A. P-384 first; a card
      // that does not do it answers 6A80 or 6A86 before changing anything, so fall back to P-256.
      byte[] point = null;
      EcCurve curve = null;
      ApduException refusal = null;
      for (EcCurve candidate : new EcCurve[] {EcCurve.P384, EcCurve.P256}) {
        try {
          byte[] generated =
              protocol.sendAndReceive(
                  new Apdu(
                      0x00,
                      INS_GENERATE_KEY,
                      0x00,
                      SLOT_AUTHENTICATION,
                      new Tlv(0xAC, new Tlv(0x80, new byte[] {candidate.algorithm}).getBytes())
                          .getBytes(),
                      AUTHENTICATE_LE));
          point = Tlvs.decodeMap(Tlvs.unpackValue(0x7F49, generated)).get(0x86);
          curve = candidate;
          break;
        } catch (ApduException e) {
          logger.info(
              "{} refused, SW=0x{}", candidate.name, String.format(Locale.ROOT, "%04x", e.getSw()));
          refusal = e;
        }
      }
      assertNotNull("The card generates neither P-384 nor P-256 keys: " + refusal, curve);
      assertNotNull("The card returned no public point", point);
      assertEquals(
          "Wrong length for an uncompressed " + curve.name + " point",
          1 + 2 * curve.coordinateLength,
          point.length);
      assertEquals("Not an uncompressed point", 0x04, point[0]);
      PublicKey cardKey = ecPublicKey(point, curve);
      logger.info("Generated {} key in slot 9A", curve.name);

      KeyPair issuer = PivTestUtils.generateKey(KeyType.ECCP384);
      byte[] certificate = PivTestUtils.createCertificate(cardKey, issuer);

      protocol.sendAndReceive(putObject(OBJECT_ID_9A, certificate));
      logger.info("Wrote a {}-byte certificate", certificate.length);

      byte[] response = protocol.sendAndReceive(getObject(OBJECT_ID_9A));
      byte[] readBack = Tlvs.decodeMap(Tlvs.unpackValue(0x53, response)).get(0x70);
      assertNotNull("The object has no certificate field", readBack);
      assertArrayEquals("The certificate read back differs", certificate, readBack);

      X509Certificate parsed =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(readBack));
      parsed.verify(issuer.getPublic());
      assertArrayEquals(
          "The certificate does not carry the key the card generated",
          cardKey.getEncoded(),
          parsed.getPublicKey().getEncoded());
      logger.info("Certificate read back intact, signature verifies, key matches the card's");
    }
  }

  /**
   * Generates an RSA-2048 key in slot 9A, which takes the card seconds and so should make it ask
   * for waiting-time extensions, stores a certificate for it, then signs with the key and verifies
   * the signature in software. <b>Replaces the key and certificate in slot 9A.</b>
   *
   * <p>The RSA signature is 256 bytes and the request that asks for it carries a 256-byte padded
   * digest, so the exchange crosses the block boundary in both directions with real cryptography to
   * prove the bytes arrived intact.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testRsaKeyGenerationSigningAndCertificateInSlot9A() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openAuthenticatedPiv(connection)) {
      long started = System.nanoTime();
      byte[] generated = generateKey(protocol, ALG_RSA2048);
      logger.info("RSA-2048 key generated in {} ms", (System.nanoTime() - started) / 1_000_000);

      Map<Integer, byte[]> fields = Tlvs.decodeMap(Tlvs.unpackValue(0x7F49, generated));
      assertNotNull("No modulus returned", fields.get(0x81));
      assertNotNull("No exponent returned", fields.get(0x82));
      PublicKey cardKey =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new RSAPublicKeySpec(
                      new BigInteger(1, fields.get(0x81)), new BigInteger(1, fields.get(0x82))));

      KeyPair issuer = PivTestUtils.generateKey(KeyType.ECCP384);
      byte[] certificate = PivTestUtils.createCertificate(cardKey, issuer);
      try {
        protocol.sendAndReceive(putObject(OBJECT_ID_9A, certificate));
        assertCertificateRoundTrip(protocol, certificate, issuer, cardKey);

        verifyPin(protocol);
        byte[] message = RandomUtils.getRandomBytes(300);
        byte[] signature = sign(protocol, ALG_RSA2048, pkcs1Sha256Block(message, 256));
        assertEquals("An RSA-2048 signature is 256 bytes", 256, signature.length);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cardKey);
        verifier.update(message);
        assertTrue(
            "The signature does not verify with the card's public key", verifier.verify(signature));
        logger.info("RSA signature from the card verifies");
      } finally {
        clearObject(protocol, OBJECT_ID_9A);
      }
    }
  }

  /**
   * Generates an ECC P-256 key in slot 9A and has the card sign several digests with it, verifying
   * each in software. <b>Replaces the key in slot 9A.</b> Every signature is a fresh exchange, so
   * the repeats also show the sequence numbers staying in step.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testEcKeySigningInSlot9A() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openAuthenticatedPiv(connection)) {
      byte[] generated = generateKey(protocol, EcCurve.P256.algorithm);
      byte[] point = Tlvs.decodeMap(Tlvs.unpackValue(0x7F49, generated)).get(0x86);
      assertNotNull("The card returned no public point", point);
      PublicKey cardKey = ecPublicKey(point, EcCurve.P256);

      verifyPin(protocol);
      for (int i = 0; i < 10; i++) {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(RandomUtils.getRandomBytes(64));
        byte[] signature = sign(protocol, EcCurve.P256.algorithm, digest);
        // The card signs the digest as given, so verify it as a raw digest.
        Signature verifier = Signature.getInstance("NONEwithECDSA");
        verifier.initVerify(cardKey);
        verifier.update(digest);
        assertTrue("Signature " + i + " does not verify", verifier.verify(signature));
      }
      logger.info("10 ECDSA signatures from the card verify");
    }
  }

  /**
   * Writes certificates of about 1, 2 and 3 KB into slot 9A, five times each, and checks every one
   * comes back identical with a valid signature. Random padding sits inside the signed part, so a
   * block lost, duplicated or reordered in either direction breaks the signature.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testLargeAndRepeatedCertificatesInSlot9A() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openAuthenticatedPiv(connection)) {
      KeyPair subject = PivTestUtils.generateKey(KeyType.ECCP256);
      KeyPair issuer = PivTestUtils.generateKey(KeyType.ECCP384);
      boolean written = false;
      try {
        for (int padding : new int[] {700, 1700, 2600}) {
          for (int round = 0; round < 5; round++) {
            byte[] certificate =
                PivTestUtils.createCertificate(
                    subject.getPublic(), issuer, RandomUtils.getRandomBytes(padding));
            try {
              protocol.sendAndReceive(putObject(OBJECT_ID_9A, certificate));
            } catch (ApduException e) {
              if (e.getSw() == SW_NOT_ENOUGH_MEMORY && written) {
                logger.info("Card is out of room at {} bytes, stopping there", certificate.length);
                return;
              }
              throw e;
            }
            written = true;
            assertCertificateRoundTrip(protocol, certificate, issuer, subject.getPublic());
          }
          logger.info("5 round trips at about {} bytes intact", padding + 340);
        }
      } finally {
        if (written) {
          clearObject(protocol, OBJECT_ID_9A);
        }
      }
    }
  }

  /** A gzip-compressed certificate, which PIV flags with a cert-info byte of 01. */
  // GzipUtils is deprecated only for being public; it stays reachable from its own package.
  @SuppressWarnings("deprecation")
  @Test
  @Category(AlwaysManualTest.class)
  public void testCompressedCertificateInSlot9A() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openAuthenticatedPiv(connection)) {
      KeyPair subject = PivTestUtils.generateKey(KeyType.ECCP256);
      KeyPair issuer = PivTestUtils.generateKey(KeyType.ECCP384);
      // Zeros compress away, so the stored form is far smaller than the certificate.
      byte[] certificate =
          PivTestUtils.createCertificate(subject.getPublic(), issuer, new byte[2000]);
      byte[] compressed = GzipUtils.compress(certificate);
      logger.info(
          "Certificate of {} bytes stored as {} bytes", certificate.length, compressed.length);
      assertTrue("The padding did not compress", compressed.length < certificate.length / 2);
      try {
        protocol.sendAndReceive(putObject(OBJECT_ID_9A, compressed, (byte) 0x01));

        Map<Integer, byte[]> object =
            Tlvs.decodeMap(
                Tlvs.unpackValue(0x53, protocol.sendAndReceive(getObject(OBJECT_ID_9A))));
        assertArrayEquals("Cert info lost", new byte[] {0x01}, object.get(0x71));
        assertArrayEquals("Compressed form differs", compressed, object.get(0x70));
        byte[] restored = GzipUtils.decompress(object.get(0x70));
        assertArrayEquals("Decompressed certificate differs", certificate, restored);
        ((X509Certificate)
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(restored)))
            .verify(issuer.getPublic());
      } finally {
        clearObject(protocol, OBJECT_ID_9A);
      }
    }
  }

  /** Writes a certificate, empties the object, and checks the card agrees it is empty. */
  @Test
  @Category(AlwaysManualTest.class)
  public void testClearCertificateInSlot9A() throws Throwable {
    try (SmartCardConnection connection = openConnection();
        SmartCardProtocol protocol = openAuthenticatedPiv(connection)) {
      KeyPair subject = PivTestUtils.generateKey(KeyType.ECCP256);
      KeyPair issuer = PivTestUtils.generateKey(KeyType.ECCP384);
      byte[] certificate = PivTestUtils.createCertificate(subject.getPublic(), issuer);
      protocol.sendAndReceive(putObject(OBJECT_ID_9A, certificate));
      assertCertificateRoundTrip(protocol, certificate, issuer, subject.getPublic());

      protocol.sendAndReceive(
          new Apdu(
              0x00,
              INS_PUT_DATA,
              0x3F,
              0xFF,
              concat(objectId(OBJECT_ID_9A), new Tlv(0x53, new byte[0]).getBytes())));
      try {
        byte[] response = protocol.sendAndReceive(getObject(OBJECT_ID_9A));
        Map<Integer, byte[]> object = Tlvs.decodeMap(Tlvs.unpackValue(0x53, response));
        assertTrue(
            "The object still has a certificate",
            object.get(0x70) == null || object.get(0x70).length == 0);
      } catch (ApduException e) {
        assertTrue(
            "Unexpected status reading the cleared object: 0x"
                + String.format(Locale.ROOT, "%04x", e.getSw()),
            e.getSw() == SW.FILE_NOT_FOUND || e.getSw() == SW.REFERENCED_DATA_NOT_FOUND);
      }
    }
  }

  private SmartCardConnection openConnection() throws Throwable {
    YubiKeyDevice currentDevice = device;
    assertNotNull("No device", currentDevice);
    SmartCardConnection connection = currentDevice.openConnection(SmartCardConnection.class);
    logger.info(
        "Transport {}, host-framed T=1: {}",
        currentDevice.getTransport(),
        !connection.isExtendedLengthApduSupported());
    return connection;
  }

  /** Short APDUs, the full PIV AID selected and the management key authenticated. */
  private static SmartCardProtocol openAuthenticatedPiv(SmartCardConnection connection)
      throws Throwable {
    SmartCardProtocol protocol = openPiv(connection);
    authenticate(protocol);
    return protocol;
  }

  /** GENERATE ASYMMETRIC KEY PAIR for slot 9A, returning the 7F49 public key template. */
  private static byte[] generateKey(SmartCardProtocol protocol, byte algorithm) throws Throwable {
    return protocol.sendAndReceive(
        new Apdu(
            0x00,
            INS_GENERATE_KEY,
            0x00,
            SLOT_AUTHENTICATION,
            new Tlv(0xAC, new Tlv(0x80, new byte[] {algorithm}).getBytes()).getBytes(),
            AUTHENTICATE_LE));
  }

  /**
   * Verifies the PIN once. The retry counter is read first, which costs nothing, and the PIN is not
   * tried at all unless a few retries are left or an earlier test already saw it refused.
   */
  private static void verifyPin(SmartCardProtocol protocol) throws Throwable {
    assertTrue("The PIN was refused earlier in this run; not trying it again", !pinRejected);

    int retries;
    try {
      protocol.sendAndReceive(new Apdu(0x00, INS_VERIFY, 0x00, PIN_REFERENCE, null));
      retries = Integer.MAX_VALUE; // already verified in this session
    } catch (ApduException e) {
      assertTrue(
          "Unexpected status reading the PIN retries: 0x"
              + String.format(Locale.ROOT, "%04x", e.getSw()),
          (e.getSw() & 0xFFF0) == 0x63C0);
      retries = e.getSw() & 0x0F;
    }
    assertTrue(
        "Only " + retries + " PIN retries left; not trying the PIN", retries >= MIN_PIN_RETRIES);

    byte[] padded = new byte[8];
    Arrays.fill(padded, (byte) 0xFF);
    System.arraycopy(PIN, 0, padded, 0, PIN.length);
    try {
      protocol.sendAndReceive(new Apdu(0x00, INS_VERIFY, 0x00, PIN_REFERENCE, padded));
    } catch (ApduException e) {
      pinRejected = true;
      fail(
          "The card refused the PIN, SW=0x"
              + String.format(Locale.ROOT, "%04x", e.getSw())
              + ". It will not be tried again.");
    }
  }

  /** GENERAL AUTHENTICATE with the key in slot 9A over {@code payload}; returns the signature. */
  private static byte[] sign(SmartCardProtocol protocol, byte algorithm, byte[] payload)
      throws Throwable {
    byte[] response =
        protocol.sendAndReceive(
            new Apdu(
                0x00,
                INS_AUTHENTICATE,
                algorithm,
                SLOT_AUTHENTICATION,
                new Tlv(
                        0x7C,
                        concat(new Tlv(0x82, null).getBytes(), new Tlv(0x81, payload).getBytes()))
                    .getBytes(),
                AUTHENTICATE_LE));
    return Tlvs.unpackValue(0x82, Tlvs.unpackValue(0x7C, response));
  }

  /** The EMSA-PKCS1-v1_5 block for a SHA-256 digest of {@code message}, as the card expects it. */
  private static byte[] pkcs1Sha256Block(byte[] message, int length) throws Exception {
    byte[] digestInfoPrefix =
        new byte[] {
          0x30,
          0x31,
          0x30,
          0x0d,
          0x06,
          0x09,
          0x60,
          (byte) 0x86,
          0x48,
          0x01,
          0x65,
          0x03,
          0x04,
          0x02,
          0x01,
          0x05,
          0x00,
          0x04,
          0x20,
        };
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);
    byte[] block = new byte[length];
    int padding = length - 3 - digestInfoPrefix.length - digest.length;
    block[1] = 0x01;
    Arrays.fill(block, 2, 2 + padding, (byte) 0xFF);
    System.arraycopy(digestInfoPrefix, 0, block, 3 + padding, digestInfoPrefix.length);
    System.arraycopy(digest, 0, block, 3 + padding + digestInfoPrefix.length, digest.length);
    return block;
  }

  /** Reads the object back and checks it is {@code certificate}, signed by {@code issuer}. */
  private static void assertCertificateRoundTrip(
      SmartCardProtocol protocol, byte[] certificate, KeyPair issuer, PublicKey subjectKey)
      throws Throwable {
    byte[] response = protocol.sendAndReceive(getObject(OBJECT_ID_9A));
    byte[] readBack = Tlvs.decodeMap(Tlvs.unpackValue(0x53, response)).get(0x70);
    assertNotNull("The object has no certificate field", readBack);
    assertArrayEquals("The certificate read back differs", certificate, readBack);

    X509Certificate parsed =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(readBack));
    parsed.verify(issuer.getPublic());
    assertArrayEquals(
        "The certificate does not carry the expected key",
        subjectKey.getEncoded(),
        parsed.getPublicKey().getEncoded());
  }

  private static void clearObject(SmartCardProtocol protocol, int objectId) {
    try {
      protocol.sendAndReceive(
          new Apdu(
              0x00,
              INS_PUT_DATA,
              0x3F,
              0xFF,
              concat(objectId(objectId), new Tlv(0x53, new byte[0]).getBytes())));
    } catch (Exception e) {
      logger.error(
          "COULD NOT CLEAR object {}: the card still holds test data",
          String.format(Locale.ROOT, "%06X", objectId),
          e);
    }
  }

  /**
   * Authenticates with the default management key, offering 3DES, AES-192 and AES-256 in turn. A
   * card that holds no key of an algorithm refuses at the first request, which costs nothing.
   */
  private static void authenticate(SmartCardProtocol protocol) throws Throwable {
    ApduException lastRefusal = null;
    for (int algorithm : new int[] {ALG_3DES, ALG_AES192, ALG_AES256}) {
      byte[] witnessRequest;
      try {
        witnessRequest =
            protocol.sendAndReceive(
                new Apdu(
                    0x00,
                    INS_AUTHENTICATE,
                    algorithm,
                    SLOT_CARD_MANAGEMENT,
                    new Tlv(0x7C, new Tlv(0x80, null).getBytes()).getBytes(),
                    AUTHENTICATE_LE));
      } catch (ApduException e) {
        lastRefusal = e;
        continue;
      }

      String cipherName = algorithm == ALG_3DES ? "DESede" : "AES";
      SecretKeySpec key =
          new SecretKeySpec(defaultManagementKey(algorithm == ALG_AES256 ? 32 : 24), cipherName);
      Cipher cipher = Cipher.getInstance(cipherName + "/ECB/NoPadding");

      byte[] witness = Tlvs.unpackValue(0x80, Tlvs.unpackValue(0x7C, witnessRequest));
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] decryptedWitness = cipher.doFinal(witness);
      byte[] challenge = RandomUtils.getRandomBytes(witness.length);

      byte[] response;
      try {
        response =
            protocol.sendAndReceive(
                new Apdu(
                    0x00,
                    INS_AUTHENTICATE,
                    algorithm,
                    SLOT_CARD_MANAGEMENT,
                    new Tlv(
                            0x7C,
                            concat(
                                new Tlv(0x80, decryptedWitness).getBytes(),
                                new Tlv(0x81, challenge).getBytes()))
                        .getBytes(),
                    AUTHENTICATE_LE));
      } catch (ApduException e) {
        fail(
            "The card rejected the default management key (SW=0x"
                + String.format(Locale.ROOT, "%04x", e.getSw())
                + "); nothing was written. Reset its management key or use another card.");
        return;
      }

      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] expected = cipher.doFinal(challenge);
      byte[] actual = Tlvs.unpackValue(0x82, Tlvs.unpackValue(0x7C, response));
      assertTrue(
          "The card failed to prove it holds the key", MessageDigest.isEqual(expected, actual));
      logger.info(
          "Authenticated with the default management key, algorithm 0x{}",
          Integer.toHexString(algorithm));
      return;
    }
    fail(
        "The card accepts none of 3DES, AES-192 or AES-256 management key authentication: "
            + lastRefusal);
  }

  private static Apdu putObject(int objectId, byte[] certificate) {
    return putObject(objectId, certificate, (byte) 0x00);
  }

  /** PUT DATA for a certificate object, {@code certInfo} being 01 for a gzip-compressed one. */
  private static Apdu putObject(int objectId, byte[] certificate, byte certInfo) {
    byte[] object =
        new Tlv(
                0x53,
                concat(
                    new Tlv(0x70, certificate).getBytes(),
                    new Tlv(0x71, new byte[] {certInfo}).getBytes(),
                    new Tlv(0xFE, new byte[0]).getBytes()))
            .getBytes();
    return new Apdu(0x00, INS_PUT_DATA, 0x3F, 0xFF, concat(objectId(objectId), object));
  }

  /** The tag list that names a data object (SP 800-73-4 Part 2, §3.1.2). */
  private static byte[] objectId(int id) {
    return new Tlv(0x5C, new byte[] {(byte) (id >> 16), (byte) (id >> 8), (byte) id}).getBytes();
  }

  private static Apdu getObject(int objectId) {
    return new Apdu(0x00, INS_GET_DATA, 0x3F, 0xFF, objectId(objectId));
  }

  /** Builds the public key from an uncompressed point on {@code curve}. */
  private static PublicKey ecPublicKey(byte[] point, EcCurve curve) throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(curve.jcaName));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
    int n = curve.coordinateLength;
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + n));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + n, 1 + 2 * n));
    return KeyFactory.getInstance("EC")
        .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
  }

  /** The curves a card may offer for slot 9A, with the algorithm byte that selects each. */
  private enum EcCurve {
    P384("P-384", "secp384r1", (byte) 0x14, 48),
    P256("P-256", "secp256r1", (byte) 0x11, 32);

    final String name;
    final String jcaName;
    final byte algorithm;
    final int coordinateLength;

    EcCurve(String name, String jcaName, byte algorithm, int coordinateLength) {
      this.name = name;
      this.jcaName = jcaName;
      this.algorithm = algorithm;
      this.coordinateLength = coordinateLength;
    }
  }

  private static byte[] concat(byte[]... parts) {
    int length = 0;
    for (byte[] part : parts) {
      length += part.length;
    }
    byte[] joined = new byte[length];
    int offset = 0;
    for (byte[] part : parts) {
      System.arraycopy(part, 0, joined, offset, part.length);
      offset += part.length;
    }
    return joined;
  }
}
