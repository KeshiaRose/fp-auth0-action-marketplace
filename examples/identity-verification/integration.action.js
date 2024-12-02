// Hard-coded token claim namespace
// https://auth0.com/docs/secure/tokens/json-web-tokens/create-namespaced-custom-claims
const claimNamespace = "https://id-verification/";

// Hard-coded user metadata namespace
// https://auth0.com/docs/manage-users/user-accounts/metadata
const metadataNamespace = "yourMetadataNamespace";

const nowInSeconds = () => Math.floor(Date.now() / 1000);

const idvRequiredCheck = (event) => {
  // https://auth0.com/docs/get-started/applications/configure-application-metadata
  const { IDV_REQUIRED } = event.client.metadata;
  return IDV_REQUIRED === "true";
};

/**
 * https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/redirect-with-actions
 *
 * @param {object} event - https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/event-object
 * @param {object} api - https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/api-object
 * @returns
 */
exports.onExecutePostLogin = async (event, api) => {
  const { TOKEN_SECRET } = event.secrets;
  const { IDV_DOMAIN, IDV_EXPIRES_IN } = event.configuration;

  const isIdvRequired = idvRequiredCheck(event);

  // Check for required configuration values.
  if (!TOKEN_SECRET || !IDV_DOMAIN) {
    // Report this issue to the logs.
    console.log("Missing required configuration.");
    if (isIdvRequired) {
      // Block the login if IDV is required for this application.
      api.access.deny("idv_configuration_error");
    }
    // Stop processing.
    return;
  }

  const {
    id: idvUserId, // User identifier from the IDV service
    lastSuccessfulCheck, // Date and time of last IDV check, UNIX timecode foramt
  } = event.user.app_metadata[metadataNamespace] || {};

  if (idvUserId) {
    // eslint-disable-next-line -- REVIEWED
    api.idToken.setCustomClaim(`${claimNamespace}id`, idvUserId);
  }

  if (
    lastSuccessfulCheck &&
    IDV_EXPIRES_IN &&
    // Last successful check has not expired.
    lastSuccessfulCheck > nowInSeconds() - parseInt(IDV_EXPIRES_IN, 10)
  ) {
    // Communicate back to the application that the IDV is valid.

    // eslint-disable-next-line -- REVIEWED
    api.idToken.setCustomClaim(`${claimNamespace}status`, "valid");

    // eslint-disable-next-line -- REVIEWED
    api.idToken.setCustomClaim(`${claimNamespace}last-check`, lastSuccessfulCheck);

    // Complete the processing.
    return;
  }

  // Non-interactive login flow but IDV is not required.
  if (!isIdvRequired && !api.redirect.canRedirect()) {
    // eslint-disable-next-line -- REVIEWED
    api.idToken.setCustomClaim(`${claimNamespace}status`, "skipped");
    return;
  }

  // Non-interactive login flow and IDV is required.
  if (isIdvRequired && !api.redirect.canRedirect()) {
    api.access.deny("idv_interaction_required");
    return;
  }

  // Set a low expiration time and include the service's user ID, if stored.
  const idvToken = api.redirect.encodeToken({
    expiresInSeconds: 10 * 60,
    payload: { id: idvUserId },
    secret: TOKEN_SECRET,
  });

  api.redirect.sendUserTo(`https://${IDV_DOMAIN}/id-verification`, {
    query: { token: idvToken },
  });
};

exports.onContinuePostLogin = async (event, api) => {
  const { TOKEN_SECRET } = event.secrets;
  const isIdvRequired = idvRequiredCheck(event);

  let tokenPayload;
  try {
    tokenPayload = api.redirect.validateToken({
      secret: TOKEN_SECRET,
      tokenParameterName: "token",
    });
  } catch (error) {
    console.log(`IDV failed when trying to validate the token: ${error.message}`);
    if (isIdvRequired) {
      api.access.deny("idv_verification_failed");
    }
    return;
  }

  const { sub: idvUserId, status: idvStatus, iat: idvLastCheck } = tokenPayload;

  if (idvStatus === "success") {
    api.user.setAppMetadata(metadataNamespace, {
      id: idvUserId,
      lastSuccessfulCheck: idvLastCheck,
    });
  } else if (isIdvRequired) {
    api.access.deny("idv_verification_failed");
    return;
  }

  // eslint-disable-next-line -- REVIEWED
  api.idToken.setCustomClaim(`${claimNamespace}status`, idvStatus);

  // eslint-disable-next-line -- REVIEWED
  api.idToken.setCustomClaim(`${claimNamespace}last-check`, idvLastCheck);

  // eslint-disable-next-line -- REVIEWED
  api.idToken.setCustomClaim(`${claimNamespace}id`, idvUserId);
};
