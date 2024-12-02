const axios = require("axios");

// Hard-coded token claim namespace
// https://auth0.com/docs/secure/tokens/json-web-tokens/create-namespaced-custom-claims
const claimNamespace = "https://your-claim-namespace/";

// Hard-coded user metadata namespace
// https://auth0.com/docs/manage-users/user-accounts/metadata
const metadataNamespace = "yourMetadataNamespace";

exports.onExecutePostLogin = async (event, api) => {
  const { API_KEY } = event.secrets;
  const { API_BASE_URL = "https://api.example.com/" } = event.configuration;

  if (!API_KEY) {
    // This will exit quietly and NOT block the current login.
    console.log("Missing required config, skipping.");
    return;
  }
  // The yourNamespace should be specific to your company or this Action.
  const currentMetadata = event.user.app_metadata[metadataNamespace];
  if (currentMetadata?.id) {
    // If we already have a link, skip the API call.
    // eslint-disable-next-line -- REVIEWED
    api.idToken.setCustomClaim(`${claimNamespace}id`, currentMetadata.id);
    return;
  }

  const postBody = {
    userEmail: event.user.email,
    userEmailVerified: event.user.email_verified,
    userPhone: event.user.phone_number,
    userPhoneVerified: event.user.phone_verified,
    userAuth0Id: event.user.user_id,
  };

  let apiResponse;
  try {
    apiResponse = await axios.post(
      `${API_BASE_URL.replace(/(.*)\/$/, "$1")}/v2/link-identity`,
      postBody,
      {
        headers: {
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );
  } catch (error) {
    // This will exit quietly and NOT block the current login.
    console.log(`Link identity call failed: ${error.message}`);
    return;
  }
  // eslint-disable-next-line -- REVIEWED
  api.idToken.setCustomClaim(`${claimNamespace}id`, apiResponse.data.id);

  api.user.setAppMetadata(metadataNamespace, { id: apiResponse.data.id });
};
