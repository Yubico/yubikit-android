/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cbor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Implements Fingerprint Bio Enrollment commands.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorConfig">authenticatorConfig</a>
 */
public class FingerprintBioEnrollment extends BioEnrollment {
  private static final int CMD_ENROLL_BEGIN = 0x01;
  private static final int CMD_ENROLL_CAPTURE_NEXT = 0x02;
  private static final int CMD_ENROLL_CANCEL = 0x03;
  private static final int CMD_ENUMERATE_ENROLLMENTS = 0x04;
  private static final int CMD_SET_NAME = 0x05;
  private static final int CMD_REMOVE_ENROLLMENT = 0x06;
  private static final int CMD_GET_SENSOR_INFO = 0x07;

  private static final int RESULT_FINGERPRINT_KIND = 0x02;
  private static final int RESULT_MAX_SAMPLES_REQUIRED = 0x03;
  private static final int RESULT_TEMPLATE_ID = 0x04;
  private static final int RESULT_LAST_SAMPLE_STATUS = 0x05;
  private static final int RESULT_REMAINING_SAMPLES = 0x06;
  private static final int RESULT_TEMPLATE_INFOS = 0x07;
  private static final int RESULT_MAX_TEMPLATE_FRIENDLY_NAME = 0x08;

  protected static final int TEMPLATE_INFO_ID = 0x01;
  protected static final int TEMPLATE_INFO_FRIENDLY_NAME = 0x02;

  private static final int PARAM_TEMPLATE_ID = 0x01;
  private static final int PARAM_TEMPLATE_FRIENDLY_NAME = 0x02;
  private static final int PARAM_TIMEOUT_MS = 0x03;

  public static final int FEEDBACK_FP_GOOD = 0x00;
  public static final int FEEDBACK_FP_TOO_HIGH = 0x01;
  public static final int FEEDBACK_FP_TOO_LOW = 0x02;
  public static final int FEEDBACK_FP_TOO_LEFT = 0x03;
  public static final int FEEDBACK_FP_TOO_RIGHT = 0x04;
  public static final int FEEDBACK_FP_TOO_FAST = 0x05;
  public static final int FEEDBACK_FP_TOO_SLOW = 0x06;
  public static final int FEEDBACK_FP_POOR_QUALITY = 0x07;
  public static final int FEEDBACK_FP_TOO_SKEWED = 0x08;
  public static final int FEEDBACK_FP_TOO_SHORT = 0x09;
  public static final int FEEDBACK_FP_MERGE_FAILURE = 0x0A;
  public static final int FEEDBACK_FP_EXISTS = 0x0B;
  // 0x0C not used
  public static final int FEEDBACK_NO_USER_ACTIVITY = 0x0D;
  public static final int FEEDBACK_NO_UP_TRANSITION = 0x0E;

  private final PinUvAuthProtocol pinUvAuth;
  private final byte[] pinUvToken;

  private final org.slf4j.Logger logger = LoggerFactory.getLogger(FingerprintBioEnrollment.class);

  public static class SensorInfo {
    public final int fingerprintKind;
    public final int maxCaptureSamplesRequiredForEnroll;
    public final int maxTemplateFriendlyName;

    public SensorInfo(
        int fingerprintKind, int maxCaptureSamplesRequiredForEnroll, int maxTemplateFriendlyName) {
      this.fingerprintKind = fingerprintKind;
      this.maxCaptureSamplesRequiredForEnroll = maxCaptureSamplesRequiredForEnroll;
      this.maxTemplateFriendlyName = maxTemplateFriendlyName;
    }

    /**
     * Indicates type of fingerprint sensor.
     *
     * @return For touch type fingerprints returns 1, for swipe type fingerprints returns 2.
     */
    public int getFingerprintKind() {
      return fingerprintKind;
    }

    /**
     * Indicates the maximum good samples required for enrollment.
     *
     * @return Maximum good samples required for enrollment.
     */
    public int getMaxCaptureSamplesRequiredForEnroll() {
      return maxCaptureSamplesRequiredForEnroll;
    }

    /**
     * Indicates the maximum number of bytes the authenticator will accept as a
     * templateFriendlyName.
     *
     * @return Maximum number of bytes the authenticator will accept as a templateFriendlyName.
     */
    public int getMaxTemplateFriendlyName() {
      return maxTemplateFriendlyName;
    }
  }

  public static class CaptureError extends Exception {
    private final int code;

    public CaptureError(int code) {
      super("Fingerprint capture error: " + code);
      this.code = code;
    }

    public int getCode() {
      return code;
    }
  }

  public static class CaptureStatus {
    private final int sampleStatus;
    private final int remaining;

    public CaptureStatus(int sampleStatus, int remaining) {
      this.sampleStatus = sampleStatus;
      this.remaining = remaining;
    }

    public int getSampleStatus() {
      return sampleStatus;
    }

    public int getRemaining() {
      return remaining;
    }
  }

  public static class EnrollBeginStatus extends CaptureStatus {
    private final byte[] templateId;

    public EnrollBeginStatus(byte[] templateId, int sampleStatus, int remaining) {
      super(sampleStatus, remaining);
      this.templateId = templateId;
    }

    public byte[] getTemplateId() {
      return templateId;
    }
  }

  /** Convenience class for handling one fingerprint enrollment */
  public static class Context {
    private final FingerprintBioEnrollment bioEnrollment;
    @Nullable private final Integer timeout;
    @Nullable private byte[] templateId;
    @Nullable private Integer remaining;

    public Context(
        FingerprintBioEnrollment bioEnrollment,
        @Nullable Integer timeout,
        @Nullable byte[] templateId,
        @Nullable Integer remaining) {
      this.bioEnrollment = bioEnrollment;
      this.timeout = timeout;
      this.templateId = templateId;
      this.remaining = remaining;
    }

    /**
     * Capture a fingerprint sample.
     *
     * <p>This call will block for up to timeout milliseconds (or indefinitely, if timeout not
     * specified) waiting for the user to scan their fingerprint to collect one sample.
     *
     * @param state If needed, the state to provide control over the ongoing operation.
     * @return None, if more samples are needed, or the template ID if enrollment is completed.
     * @throws IOException A communication error in the transport layer.
     * @throws CommandException A communication error in the protocol layer.
     * @throws CaptureError An error during fingerprint capture.
     */
    @Nullable
    public byte[] capture(@Nullable CommandState state)
        throws IOException, CommandException, CaptureError {
      int sampleStatus;
      if (templateId == null) {
        final EnrollBeginStatus status = bioEnrollment.enrollBegin(timeout, state);
        templateId = status.getTemplateId();
        remaining = status.getRemaining();
        sampleStatus = status.getSampleStatus();
      } else {
        final CaptureStatus status = bioEnrollment.enrollCaptureNext(templateId, timeout, state);
        remaining = status.getRemaining();
        sampleStatus = status.getSampleStatus();
      }

      if (sampleStatus != FEEDBACK_FP_GOOD) {
        throw new CaptureError(sampleStatus);
      }

      if (remaining == 0) {
        return templateId;
      }
      return null;
    }

    /** Cancels ongoing enrollment. */
    public void cancel() throws IOException, CommandException {
      bioEnrollment.enrollCancel();
      templateId = null;
    }

    /**
     * @return number of remaining captures for successful enrollment
     */
    @Nullable
    public Integer getRemaining() {
      return remaining;
    }
  }

  public FingerprintBioEnrollment(
      Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol, byte[] pinUvToken)
      throws IOException, CommandException {
    super(ctap, BioEnrollment.MODALITY_FINGERPRINT);
    this.pinUvAuth = pinUvAuthProtocol;
    this.pinUvToken = pinUvToken;
  }

  private Map<Integer, ?> call(
      Integer subCommand, @Nullable Map<?, ?> subCommandParams, @Nullable CommandState state)
      throws IOException, CommandException {
    return call(subCommand, subCommandParams, state, true);
  }

  private Map<Integer, ?> call(
      Integer subCommand,
      @Nullable Map<?, ?> subCommandParams,
      @Nullable CommandState state,
      boolean authenticate)
      throws IOException, CommandException {
    byte[] pinUvAuthParam = null;
    if (authenticate) {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      output.write(MODALITY_FINGERPRINT);
      output.write(subCommand);
      if (subCommandParams != null) {
        Cbor.encodeTo(output, subCommandParams);
      }
      pinUvAuthParam = pinUvAuth.authenticate(pinUvToken, output.toByteArray());
    }

    return ctap.bioEnrollment(
        modality,
        subCommand,
        subCommandParams,
        pinUvAuth.getVersion(),
        pinUvAuthParam,
        null,
        state);
  }

  /**
   * Get fingerprint sensor info.
   *
   * @return A dict containing FINGERPRINT_KIND, MAX_SAMPLES_REQUIRES and
   *     MAX_TEMPLATE_FRIENDLY_NAME.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getFingerprintSensorInfo">Get
   *     fingerprint sensor info</a>
   */
  public SensorInfo getSensorInfo() throws IOException, CommandException {

    final Map<Integer, ?> result =
        ctap.bioEnrollment(MODALITY_FINGERPRINT, CMD_GET_SENSOR_INFO, null, null, null, null, null);

    return new SensorInfo(
        Objects.requireNonNull((Integer) result.get(RESULT_FINGERPRINT_KIND)),
        Objects.requireNonNull((Integer) result.get(RESULT_MAX_SAMPLES_REQUIRED)),
        Objects.requireNonNull((Integer) result.get(RESULT_MAX_TEMPLATE_FRIENDLY_NAME)));
  }

  /**
   * Start fingerprint enrollment.
   *
   * <p>Starts the process of enrolling a new fingerprint, and will wait for the user to scan their
   * fingerprint once to provide an initial sample.
   *
   * @param timeout Optional timeout in milliseconds.
   * @param state If needed, the state to provide control over the ongoing operation.
   * @return A status object containing the new template ID, the sample status, and the number of
   *     samples remaining to complete the enrollment.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enrollingFingerprint">Enrolling
   *     fingerprint</a>
   */
  public EnrollBeginStatus enrollBegin(@Nullable Integer timeout, @Nullable CommandState state)
      throws IOException, CommandException {
    Logger.debug(logger, "Starting fingerprint enrollment");

    Map<Integer, Object> parameters = new HashMap<>();
    if (timeout != null) parameters.put(PARAM_TIMEOUT_MS, timeout);

    final Map<Integer, ?> result = call(CMD_ENROLL_BEGIN, parameters, state);
    Logger.debug(logger, "Sample capture result: {}", result);
    return new EnrollBeginStatus(
        Objects.requireNonNull((byte[]) result.get(RESULT_TEMPLATE_ID)),
        Objects.requireNonNull((Integer) result.get(RESULT_LAST_SAMPLE_STATUS)),
        Objects.requireNonNull((Integer) result.get(RESULT_REMAINING_SAMPLES)));
  }

  /**
   * Continue fingerprint enrollment.
   *
   * <p>Continues enrolling a new fingerprint and will wait for the user to scan their fingerprint
   * once to provide a new sample. Once the number of samples remaining is 0, the enrollment is
   * completed.
   *
   * @param templateId The template ID returned by a call to {@link #enrollBegin(Integer timeout,
   *     CommandState state)}.
   * @param timeout Optional timeout in milliseconds.
   * @param state If needed, the state to provide control over the ongoing operation.
   * @return A status object containing the sample status, and the number of samples remaining to
   *     complete the enrollment.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enrollingFingerprint">Enrolling
   *     fingerprint</a>
   */
  public CaptureStatus enrollCaptureNext(
      byte[] templateId, @Nullable Integer timeout, @Nullable CommandState state)
      throws IOException, CommandException {
    Logger.debug(
        logger,
        "Capturing next sample with (timeout={})",
        timeout != null ? timeout : "none specified");

    Map<Integer, Object> parameters = new HashMap<>();
    parameters.put(PARAM_TEMPLATE_ID, templateId);
    if (timeout != null) parameters.put(PARAM_TIMEOUT_MS, timeout);

    final Map<Integer, ?> result = call(CMD_ENROLL_CAPTURE_NEXT, parameters, state);
    Logger.debug(logger, "Sample capture result: {}", result);
    return new CaptureStatus(
        Objects.requireNonNull((Integer) result.get(RESULT_LAST_SAMPLE_STATUS)),
        Objects.requireNonNull((Integer) result.get(RESULT_REMAINING_SAMPLES)));
  }

  /**
   * Cancel any ongoing fingerprint enrollment.
   *
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#cancelEnrollment">Cancel
   *     current enrollment</a>
   */
  public void enrollCancel() throws IOException, CommandException {
    Logger.debug(logger, "Cancelling fingerprint enrollment.");
    call(CMD_ENROLL_CANCEL, null, null, false);
  }

  /**
   * Convenience wrapper for doing fingerprint enrollment.
   *
   * @param timeout Optional timeout in milliseconds.
   * @return An initialized FingerprintEnrollment.Context.
   * @see FingerprintBioEnrollment.Context
   */
  public Context enroll(@Nullable Integer timeout) {
    return new Context(this, timeout, null, null);
  }

  /**
   * Get a dict of enrolled fingerprint templates which maps template ID's to their friendly names.
   *
   * @return A Map of enrolled templateId -> name pairs.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enumerateEnrollments">Enumerate
   *     enrollments</a>
   */
  public Map<byte[], String> enumerateEnrollments() throws IOException, CommandException {
    try {
      final Map<Integer, ?> result = call(CMD_ENUMERATE_ENROLLMENTS, null, null);

      @SuppressWarnings("unchecked")
      final List<Map<Integer, ?>> infos = (List<Map<Integer, ?>>) result.get(RESULT_TEMPLATE_INFOS);
      final Map<byte[], String> enrollments = new HashMap<>();
      for (Map<Integer, ?> info : infos) {
        final byte[] id = Objects.requireNonNull((byte[]) info.get(TEMPLATE_INFO_ID));
        @Nullable String friendlyName = (String) info.get(TEMPLATE_INFO_FRIENDLY_NAME);
        // treat empty strings as null values
        if (friendlyName != null) {
          friendlyName = friendlyName.trim();
          if (friendlyName.isEmpty()) {
            friendlyName = null;
          }
        }
        enrollments.put(id, friendlyName);
      }

      return enrollments;
    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_INVALID_OPTION) {
        return Collections.emptyMap();
      }
      throw e;
    }
  }

  /**
   * Set/Change the friendly name of a previously enrolled fingerprint template.
   *
   * @param templateId The ID of the template to change.
   * @param name A friendly name to give the template.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setFriendlyName">Rename/Set
   *     FriendlyName</a>
   */
  public void setName(byte[] templateId, String name) throws IOException, CommandException {
    Logger.debug(
        logger, "Changing name of template: {} {}", Base64.toUrlSafeString(templateId), name);

    Map<Integer, Object> parameters = new HashMap<>();
    parameters.put(PARAM_TEMPLATE_ID, templateId);
    parameters.put(PARAM_TEMPLATE_FRIENDLY_NAME, name);

    call(CMD_SET_NAME, parameters, null);
    Logger.info(logger, "Fingerprint template renamed");
  }

  /**
   * Remove a previously enrolled fingerprint template.
   *
   * @param templateId The Id of the template to remove.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication error in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#removeEnrollment">Remove
   *     enrollment</a>
   */
  public void removeEnrollment(byte[] templateId) throws IOException, CommandException {
    Logger.debug(logger, "Deleting template: {}", Base64.toUrlSafeString(templateId));

    Map<Integer, Object> parameters = new HashMap<>();
    parameters.put(PARAM_TEMPLATE_ID, templateId);

    call(CMD_REMOVE_ENROLLMENT, parameters, null);
    Logger.info(logger, "Fingerprint template deleted");
  }
}
