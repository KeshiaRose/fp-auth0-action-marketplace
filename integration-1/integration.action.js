const {
  FingerprintJsServerApiClient,
  Region,
  RequestError,
} = require("@fingerprintjs/fingerprintjs-pro-server-api");

/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  let {
    REGION,
    IDENTIFICATION_ERROR,
    UNRECOGNIZED_VISITORID,
    MAX_SUSPECT_SCORE,
    BOT_DETECTION,
    VPN_DETECTION,
    DENIED_MESSAGE,
  } = event.configuration;

  const { FINGERPRINT_SECRET_API_KEY } = event.secrets;

  // Helper function to validate configuration values
  function validateConfig(value, allowedValues, defaultValue) {
    return allowedValues.includes(value) ? value : defaultValue;
  }

  // Validate configurations
  REGION = validateConfig(REGION, ["Global", "EU", "AP"], "Global");
  IDENTIFICATION_ERROR = validateConfig(
    IDENTIFICATION_ERROR,
    ["block_login", "allow_login"],
    "block_login"
  );
  UNRECOGNIZED_VISITORID = validateConfig(
    UNRECOGNIZED_VISITORID,
    ["trigger_mfa", "allow_login"],
    "trigger_mfa"
  );
  BOT_DETECTION = validateConfig(
    BOT_DETECTION,
    ["block_login", "trigger_mfa", "allow_login"],
    "block_login"
  );
  VPN_DETECTION = validateConfig(
    VPN_DETECTION,
    ["block_login", "trigger_mfa", "allow_login"],
    "allow_login"
  );
  MAX_SUSPECT_SCORE = MAX_SUSPECT_SCORE === "-1" ? -1 : parseInt(MAX_SUSPECT_SCORE, 10) || -1;
  DENIED_MESSAGE = DENIED_MESSAGE || "Error logging in.";

  let mfaNeeded = false;

  // Helper function to handle Fingerprint errors
  function handleFpError(msg) {
    console.log(msg);
    api.user.setAppMetadata("fp_skip", true);
    if (IDENTIFICATION_ERROR === "block_login") {
      return api.access.deny(DENIED_MESSAGE);
    }
    // Continue login if set to 'allow_login'
    return null;
  }

  const client = new FingerprintJsServerApiClient({
    region: Region[REGION],
    apiKey: FINGERPRINT_SECRET_API_KEY,
  });

  // Extract the requestId from the query parameters
  const { requestId } = event.request.query;
  if (!requestId) {
    handleFpError("Fingerprint request ID missing.");
    return;
  }

  // Fetch the identification event using the requestId
  let identificationEvent;
  try {
    identificationEvent = await client.getEvent(requestId);
  } catch (error) {
    if (error instanceof RequestError) {
      console.log(error.responseBody); // Access parsed response body
      console.log(error.response); // You can also access the raw response
      console.log(`error ${error.statusCode}: `, error.message);
    } else {
      console.log("Unknown FP error: ", error);
    }
    handleFpError("Fingerprint identification event not found");
    return;
  }
  const visitorId = identificationEvent?.products?.identification?.data?.visitorId;
  if (!visitorId) {
    handleFpError("Fingerprint visitor ID not found.");
    return;
  }

  // Save the current visitorId within the app metadata
  api.user.setAppMetadata("fp_currentVisitorId", visitorId);

  // Detect bot actitivity and handle accordingly
  const botDetection = identificationEvent?.products?.botd?.data?.bot?.result;
  if (botDetection !== "notDetected") {
    if (BOT_DETECTION === "block_login") {
      api.access.deny(DENIED_MESSAGE);
      return;
    }
    if (BOT_DETECTION === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // Detect VPN usage and handle accordingly
  const vpnDetected = identificationEvent?.products?.vpn?.data?.result;
  if (vpnDetected) {
    if (VPN_DETECTION === "block_login") {
      api.access.deny(DENIED_MESSAGE);
      return;
    }
    if (VPN_DETECTION === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // Check if the visitor's Suspect Score is above the threshold
  const suspectScore = identificationEvent?.products?.identification?.data?.suspect?.score;
  if (suspectScore > MAX_SUSPECT_SCORE && MAX_SUSPECT_SCORE >= 0) {
    mfaNeeded = true;
  }

  // Check if the visitorId is recognized
  const appMetadata = event.user.app_metadata || {};
  if (!appMetadata.fp_visitorIds || !appMetadata.fp_visitorIds.includes(visitorId)) {
    if (UNRECOGNIZED_VISITORID === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // If not enrolled in MFA, enroll in MFA
  const enrolledMFAs = event?.user?.multifactor?.length;
  if (!enrolledMFAs || enrolledMFAs === 0) {
    api.user.setAppMetadata("fp_mfaNeeded", true);
    api.authentication.enrollWithAny([
      { type: "otp" },
      { type: "recovery-code" },
      { type: "push-notification" },
      { type: "phone" },
      { type: "webauthn-platform" },
      { type: "webauthn-roaming" },
    ]);
    return;
  }

  // Otherwise if MFA needed, trigger MFA
  if (mfaNeeded) {
    api.user.setAppMetadata("fp_mfaNeeded", true);
    api.authentication.challengeWithAny([
      { type: "otp" },
      { type: "recovery-code" },
      { type: "email" },
      { type: "push-notification" },
      { type: "phone" },
      { type: "webauthn-platform" },
      { type: "webauthn-roaming" },
    ]);
  }
};
