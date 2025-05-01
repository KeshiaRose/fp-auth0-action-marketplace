/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  const { DENIED_MESSAGE, EXPOSE_VISITOR_IDS } = event.configuration;

  const VALID_DENIED_MESSAGE = DENIED_MESSAGE || "Error logging in.";
  const VALID_EXPOSE_VISITOR_IDS =
    (["true", "false"].includes(EXPOSE_VISITOR_IDS) ? EXPOSE_VISITOR_IDS : "false") === "true";

  // Get variables from the first Action
  const appMetadata = event.user.app_metadata || {};
  const skipFp = appMetadata.com_fingerprint_skip;
  const visitorId = appMetadata.com_fingerprint_currentVisitorId;
  const mfaNeeded = appMetadata.com_fingerprint_mfaNeeded;
  api.user.setAppMetadata("com_fingerprint_skip", null);
  api.user.setAppMetadata("com_fingerprint_currentVisitorId", null);
  api.user.setAppMetadata("com_fingerprint_mfaNeeded", null);

  if (skipFp) return;

  // If no visitorId has been passed there is an error in the Action
  if (!visitorId) {
    api.access.deny(VALID_DENIED_MESSAGE);
    return;
  }

  // Check if the user successfully completed authentication and MFA if was needed
  if (!event.authentication) {
    api.access.deny(VALID_DENIED_MESSAGE);
    return;
  }
  const mfaSuccess = event.authentication.methods.find((m) => m.name === "mfa");
  if (mfaNeeded && !mfaSuccess) {
    api.access.deny(VALID_DENIED_MESSAGE);
    return;
  }

  // If successfully passed all checks, associate the visitorId with the user
  const updatedVisitorIds = appMetadata.com_fingerprint_visitorIds || [];
  if (!updatedVisitorIds.includes(visitorId)) {
    // Update the app_metadata with the new visitorId
    updatedVisitorIds.push(visitorId);
    api.user.setAppMetadata("com_fingerprint_visitorIds", updatedVisitorIds);
  }

  // Optional: Set the visitorId list as a custom claim so it can be accessed from the app
  if (VALID_EXPOSE_VISITOR_IDS) {
    api.idToken.setCustomClaim("https://fingerprint.com/visitorIds", updatedVisitorIds);
  }
};
