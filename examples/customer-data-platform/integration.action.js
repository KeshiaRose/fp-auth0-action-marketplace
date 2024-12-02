const axios = require("axios");

const skipProtocols = ["oauth2-access-token", "oauth2-refresh-token", "oauth2-token-exchange"];

/**
 * https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/redirect-with-actions
 *
 * @param {object} event - https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/event-object
 * @param {object} api - https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/api-object
 * @returns
 */
exports.onExecutePostLogin = async (event) => {
  // We are skipping login event types that follow a login event.
  if (skipProtocols.includes(event.transaction.protocol)) {
    console.log(`CDP skipped for protocol ${event.transaction.protocol}.`);
    return;
  }

  const { CDP_API_KEY } = event.secrets;

  // Change event.configuration to event.secrets if copy/pasting into a custom Action.
  const { CDP_BASE_URL = "https://api.example.com/" } = event.configuration;

  // Fail silently if not properly configured.
  if (!CDP_API_KEY) {
    console.log("CDP missing required configuration.");
    return;
  }

  // This maps Auth0 strategy names to what the CDP expects.
  const identityConnectionMap = {
    facebook: "facebook",
    twitter: "twitter",
    "google-oauth2": "google",
    windowslive: "microsoft",
  };

  const userIdentities = Object.fromEntries(
    event.user.identities
      .filter((identity) => Object.keys(identityConnectionMap).includes(identity.provider))
      .map((identity) => [identityConnectionMap[identity.provider], identity.user_id])
  );

  const location = {};
  if (event.request.geoip) {
    location.latitude = event.request.geoip.latitude;
    location.longitude = event.request.geoip.longitude;
    location.country_code = event.request.geoip.countryCode;
    location.city_name = event.request.geoip.cityName;
  }

  const eventPost = {
    events_attributes: {
      // First counted login is registration.
      name: event.stats.logins_count > 1 ? "login" : "registration",
    },
    user_attributes: {
      // https://auth0.com/docs/manage-users/user-accounts/user-profiles/user-profile-structure
      first_name: event.user.given_name,
      last_name: event.user.family_name,
      phone_number: event.user.phone_number,
    },
    user_identities: {
      email: event.user.email,
      auth0_user_id: event.user.user_id,
      ...userIdentities,
    },
    application_attributes: {
      name: event.client.name,
    },
    ip: event.request.ip,
    location,
  };

  try {
    await axios.post(`${CDP_BASE_URL.replace(/(.*)\/$/, "$1")}/v2/events`, eventPost, {
      headers: {
        Authorization: `Bearer ${CDP_API_KEY}`,
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.log(`CDP API call failed: ${error.message}`);
  }
};
