const axios = require("axios");

exports.onExecutePostLogin = async (event, api) => {
  const { API_KEY } = event.secrets;
  const { API_BASE_URL = "https://api.example.com", RISK_SCORE_THRESHOLD } = event.configuration;

  if (!API_KEY) {
    console.log("Missing required API key, skipping.");
    return;
  }

  const riskScoreBody = {
    userEmail: event.user.email,
    userEmailVerified: event.user.email_verified,
    userPhone: event.user.phone_number,
    userPhoneVerified: event.user.phone_verified,
    loginIp: event.request.ip,
    loginUserAgent: event.request.user_agent,
  };

  if (event.request.geoip) {
    riskScoreBody.location = {
      latitude: event.request.geoip.latitude,
      longitude: event.request.geoip.longitude,
      countryCode: event.request.geoip.countryCode,
      cityName: event.request.geoip.cityName,
    };
  }

  let apiResponse;
  try {
    apiResponse = await axios.post(
      `${API_BASE_URL.replace(/(.*)\/$/, "$1")}/v2/risk`,
      riskScoreBody,
      {
        headers: {
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );
  } catch (error) {
    api.access.deny("api_request_failed");
    return;
  }

  const riskScoreThreshold = parseInt(RISK_SCORE_THRESHOLD, 10);

  if (riskScoreThreshold >= 1 && apiResponse.data.score > riskScoreThreshold) {
    api.access.deny("risk_score_threshold_reached");
    return;
  }

  api.idToken.setCustomClaim("https://risk/score", apiResponse.data.score);
};
