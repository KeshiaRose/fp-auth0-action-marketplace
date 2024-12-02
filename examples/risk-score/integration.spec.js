const { faker } = require("@faker-js/faker");

jest.mock("axios");
const axiosMock = require("axios");

const { makeEventMock } = require("../__mocks__/event-post-login");
const { apiMock } = require("../__mocks__/api-post-login");

const { onExecutePostLogin } = require("./integration.action");

describe("Risk score API", () => {
  let consoleLogMock;
  let eventMock;

  beforeEach(() => {
    consoleLogMock = jest.spyOn(console, "log").mockImplementation();
    eventMock = makeEventMock();
  });

  afterEach(() => {
    consoleLogMock.mockRestore();
    axiosMock.mockClear();
  });

  describe("skipped", () => {
    it("skips the action when config is missing", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(consoleLogMock).toBeCalledWith("Missing required API key, skipping.");
    });
  });

  describe("failed API response", () => {
    beforeEach(async () => {
      eventMock.secrets.API_KEY = faker.datatype.uuid();
      axiosMock.shouldReturnError(true);
      await onExecutePostLogin(eventMock, apiMock);
    });

    it("stops the login", async () => {
      expect(apiMock.access.deny).toBeCalledWith("api_request_failed");
    });
  });

  describe("success", () => {
    beforeEach(async () => {
      eventMock.secrets.API_KEY = faker.datatype.uuid();
      axiosMock.shouldReturnError(false);
      axiosMock.shouldReturnData({ data: { score: 5 } });
    });

    it("makes the correct HTTP call", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post).toBeCalledWith(
        "https://api.example.com/v2/risk",
        {
          userEmail: eventMock.user.email,
          userEmailVerified: eventMock.user.email_verified,
          userPhone: eventMock.user.phone_number,
          userPhoneVerified: eventMock.user.phone_verified,
          loginIp: eventMock.request.ip,
          loginUserAgent: eventMock.request.user_agent,
          location: {
            latitude: eventMock.request.geoip.latitude,
            longitude: eventMock.request.geoip.longitude,
            countryCode: eventMock.request.geoip.countryCode,
            cityName: eventMock.request.geoip.cityName,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${eventMock.secrets.API_KEY}`,
          },
        }
      );
    });

    it("uses a custom base URL", async () => {
      eventMock.configuration.API_BASE_URL = faker.internet.url();
      delete eventMock.request.geoip;
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post).toHaveBeenLastCalledWith(
        `${eventMock.configuration.API_BASE_URL}/v2/risk`,
        {
          userEmail: eventMock.user.email,
          userEmailVerified: eventMock.user.email_verified,
          userPhone: eventMock.user.phone_number,
          userPhoneVerified: eventMock.user.phone_verified,
          loginIp: eventMock.request.ip,
          loginUserAgent: eventMock.request.user_agent,
        },
        {
          headers: {
            Authorization: `Bearer ${eventMock.secrets.API_KEY}`,
          },
        }
      );
    });

    it("sets a custom claim", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(apiMock.idToken.setCustomClaim).toBeCalledWith("https://risk/score", 5);
    });

    it("rejects login based on a threshold", async () => {
      eventMock.configuration.RISK_SCORE_THRESHOLD = 4;
      await onExecutePostLogin(eventMock, apiMock);
      expect(apiMock.access.deny).toBeCalledWith("risk_score_threshold_reached");
    });
  });
});
