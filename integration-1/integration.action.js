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
  const {
    REGION,
    IDENTIFICATION_ERROR,
    UNRECOGNIZED_VISITORID,
    MAX_SUSPECT_SCORE,
    BOT_DETECTION,
    VPN_DETECTION,
    AVAILABLE_MFA,
    DENIED_MESSAGE,
  } = event.configuration;

  const { FINGERPRINT_SECRET_API_KEY } = event.secrets;

  // Helper function to validate configuration values
  function validateConfig(value, allowedValues, defaultValue) {
    return allowedValues.includes(value) ? value : defaultValue;
  }

  // Validate configurations
  const VALID_DENIED_MESSAGE = DENIED_MESSAGE || "Error logging in.";
  const VALID_IDENTIFICATION_ERROR = validateConfig(
    IDENTIFICATION_ERROR,
    ["block_login", "allow_login"],
    "block_login"
  );
  const VALID_REGION = validateConfig(REGION, ["Global", "EU", "AP"], "Global");
  const VALID_UNRECOGNIZED_VISITORID = validateConfig(
    UNRECOGNIZED_VISITORID,
    ["trigger_mfa", "allow_login"],
    "trigger_mfa"
  );
  const VALID_BOT_DETECTION = validateConfig(
    BOT_DETECTION,
    ["block_login", "trigger_mfa", "allow_login"],
    "block_login"
  );
  const VALID_VPN_DETECTION = validateConfig(
    VPN_DETECTION,
    ["block_login", "trigger_mfa", "allow_login"],
    "allow_login"
  );
  const VALID_MAX_SUSPECT_SCORE =
    MAX_SUSPECT_SCORE === "-1" ? -1 : parseInt(MAX_SUSPECT_SCORE, 10) || -1;

  // Helper function to handle Action errors
  function handleActionError(msg) {
    console.log(msg);
    api.user.setAppMetadata("com_fingerprint_skip", true);
    if (VALID_IDENTIFICATION_ERROR === "block_login") {
      return api.access.deny(VALID_DENIED_MESSAGE);
    }
    // Continue login if set to 'allow_login'
    return null;
  }

  let VALID_AVAILABLE_MFA;
  try {
    const splitList = AVAILABLE_MFA.replace(/ /g, "")
      .split(",")
      .filter((mfa) => mfa !== "");
    if (splitList.length === 0) throw new Error();
    VALID_AVAILABLE_MFA = splitList.map((mfa) => ({ type: mfa }));
  } catch (error) {
    handleActionError("Invalid MFA configuration.");
    return;
  }
  if (VALID_AVAILABLE_MFA.length === 0) {
    handleActionError("No MFA methods configured.");
    return;
  }
  if (!FINGERPRINT_SECRET_API_KEY) {
    handleActionError("Fingerprint API key is missing.");
    return;
  }

  let mfaNeeded = false;

  // Initialize the Fingerprint Server API client
  const client = new FingerprintJsServerApiClient({
    region: Region[VALID_REGION],
    apiKey: FINGERPRINT_SECRET_API_KEY,
  });

  // Extract the requestId from the query parameters
  const { requestId } = event.request.query;
  if (!requestId) {
    handleActionError("Fingerprint request ID missing.");
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
    handleActionError("Fingerprint identification event not found");
    return;
  }
  const visitorId = identificationEvent?.products?.identification?.data?.visitorId;
  if (!visitorId) {
    handleActionError("Fingerprint visitor ID not found.");
    return;
  }

  // Save the current visitorId within the app metadata
  api.user.setAppMetadata("com_fingerprint_currentVisitorId", visitorId);

  // Detect bot actitivity and handle accordingly
  const botDetection = identificationEvent?.products?.botd?.data?.bot?.result;
  if (botDetection !== "notDetected") {
    if (VALID_BOT_DETECTION === "block_login") {
      api.access.deny(VALID_DENIED_MESSAGE);
      return;
    }
    if (VALID_BOT_DETECTION === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // Detect VPN usage and handle accordingly
  const vpnDetected = identificationEvent?.products?.vpn?.data?.result;
  if (vpnDetected) {
    if (VALID_VPN_DETECTION === "block_login") {
      api.access.deny(VALID_DENIED_MESSAGE);
      return;
    }
    if (VALID_VPN_DETECTION === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // Check if the visitor's Suspect Score is above the threshold
  const suspectScore = identificationEvent?.products?.identification?.data?.suspect?.score;
  if (suspectScore > VALID_MAX_SUSPECT_SCORE && VALID_MAX_SUSPECT_SCORE >= 0) {
    mfaNeeded = true;
  }

  // Check if the visitorId is recognized
  const appMetadata = event.user.app_metadata || {};
  if (
    !appMetadata.com_fingerprint_visitorIds ||
    !appMetadata.com_fingerprint_visitorIds.includes(visitorId)
  ) {
    if (VALID_UNRECOGNIZED_VISITORID === "trigger_mfa") {
      mfaNeeded = true;
    }
    // Continue login if set to 'allow_login'
  }

  // If not enrolled in MFA, enroll in MFA
  const enrolledMFAs = event.user?.enrolledFactors || [];
  const formattedEnrolledMFAs = enrolledMFAs.map((mfa) => ({ type: mfa.type }));
  if (!enrolledMFAs || enrolledMFAs.length === 0) {
    api.user.setAppMetadata("com_fingerprint_mfaNeeded", true);
    api.authentication.enrollWithAny(VALID_AVAILABLE_MFA);
    return;
  }

  // Otherwise if MFA needed, trigger MFA
  if (mfaNeeded) {
    api.user.setAppMetadata("com_fingerprint_mfaNeeded", true);
    api.authentication.challengeWithAny(formattedEnrolledMFAs);
  }
};
