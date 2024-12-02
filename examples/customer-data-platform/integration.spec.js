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
    eventMock.transaction = { protocol: "oidc-basic-profile" };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("skipped", () => {
    it("skips the action when we are doing a refresh token grant", async () => {
      eventMock.transaction.protocol = "oauth2-refresh-token";
      await onExecutePostLogin(eventMock, apiMock);
      expect(consoleLogMock).toBeCalledWith("CDP skipped for protocol oauth2-refresh-token.");
    });

    it("skips the action when config is missing", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(consoleLogMock).toBeCalledWith("CDP missing required configuration.");
    });
  });

  describe("failed API response", () => {
    beforeEach(async () => {
      eventMock.secrets.CDP_API_KEY = faker.datatype.uuid();
      axiosMock.shouldReturnError(true);
      await onExecutePostLogin(eventMock, apiMock);
    });

    it("does not stop the login", async () => {
      expect(apiMock.access.deny).not.toBeCalled();
    });

    it("logs the error", async () => {
      expect(consoleLogMock).toBeCalledWith("CDP API call failed: __TEST_ERROR_MESSAGE__");
    });
  });

  describe("success", () => {
    beforeEach(async () => {
      eventMock.secrets.CDP_API_KEY = faker.datatype.uuid();
      eventMock.stats.logins_count = 2;
    });

    it("makes the correct HTTP call to the default endpoint", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post).toBeCalledWith(
        "https://api.example.com/v2/events",
        {
          events_attributes: {
            name: "login",
          },
          user_attributes: {
            first_name: eventMock.user.given_name,
            last_name: eventMock.user.family_name,
            phone_number: eventMock.user.phone_number,
          },
          user_identities: {
            email: eventMock.user.email,
            auth0_user_id: eventMock.user.user_id,
          },
          application_attributes: {
            name: eventMock.client.name,
          },
          ip: eventMock.request.ip,
          location: {
            latitude: eventMock.request.geoip.latitude,
            longitude: eventMock.request.geoip.longitude,
            country_code: eventMock.request.geoip.countryCode,
            city_name: eventMock.request.geoip.cityName,
          },
        },
        {
          headers: {
            Authorization: `Bearer ${eventMock.secrets.CDP_API_KEY}`,
            "Content-Type": "application/json",
          },
        }
      );
    });

    it("makes the correct HTTP call to a custom endpoint", async () => {
      eventMock.configuration.CDP_BASE_URL = faker.internet.url();
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post.mock.calls[0][0]).toEqual(
        `${eventMock.configuration.CDP_BASE_URL}/v2/events`
      );
    });
  });

  describe("identity mapping", () => {
    beforeEach(async () => {
      eventMock.secrets.CDP_API_KEY = faker.datatype.uuid();
    });

    it("maps google identities", async () => {
      const userId = faker.datatype.uuid();
      eventMock.user.identities = [
        {
          provider: "google-oauth2",
          user_id: userId,
        },
      ];
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post.mock.calls[0][1].user_identities.google).toEqual(userId);
    });

    it("maps twitter identities", async () => {
      const userId = faker.datatype.uuid();
      eventMock.user.identities = [
        {
          provider: "twitter",
          user_id: userId,
        },
      ];
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post.mock.calls[0][1].user_identities.twitter).toEqual(userId);
    });

    it("maps microsoft identities", async () => {
      const userId = faker.datatype.uuid();
      eventMock.user.identities = [
        {
          provider: "windowslive",
          user_id: userId,
        },
      ];
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post.mock.calls[0][1].user_identities.microsoft).toEqual(userId);
    });

    it("maps facebook identities", async () => {
      const userId = faker.datatype.uuid();
      eventMock.user.identities = [
        {
          provider: "facebook",
          user_id: userId,
        },
      ];
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post.mock.calls[0][1].user_identities.facebook).toEqual(userId);
    });
  });
});
