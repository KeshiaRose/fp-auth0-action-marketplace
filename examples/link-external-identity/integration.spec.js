const { faker } = require("@faker-js/faker");

jest.mock("axios");
const axiosMock = require("axios");

const { eventMock } = require("../__mocks__/event-post-login");
const { apiMock } = require("../__mocks__/api-post-login");

const { onExecutePostLogin } = require("./integration.action");

describe("Risk score API", () => {
  let consoleLogMock;

  beforeEach(() => {
    consoleLogMock = jest.spyOn(console, "log").mockImplementation();
  });

  afterEach(() => {
    jest.clearAllMocks();
    eventMock.secrets = {};
    eventMock.user.app_metadata = {};
  });

  describe("skipped", () => {
    it("skips the action when config is missing", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(consoleLogMock).toBeCalledWith("Missing required config, skipping.");
    });
  });

  describe("already has ID", () => {
    it("adds the ID to a custom claim", async () => {
      eventMock.secrets.API_KEY = faker.datatype.uuid();
      eventMock.user.app_metadata.yourMetadataNamespace = { id: faker.datatype.number() };
      await onExecutePostLogin(eventMock, apiMock);
      expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
        "https://your-claim-namespace/id",
        eventMock.user.app_metadata.yourMetadataNamespace.id
      );
    });
  });

  describe("failed API response", () => {
    beforeEach(async () => {
      eventMock.secrets.API_KEY = faker.datatype.uuid();
      axiosMock.shouldReturnError(true);
      await onExecutePostLogin(eventMock, apiMock);
    });

    it("does not stop the login", async () => {
      expect(apiMock.access.deny).not.toBeCalled();
    });

    it("logs the error", async () => {
      expect(consoleLogMock).toBeCalledWith("Link identity call failed: __TEST_ERROR_MESSAGE__");
    });
  });

  describe("success", () => {
    beforeEach(async () => {
      eventMock.secrets.API_KEY = faker.datatype.uuid();
      axiosMock.shouldReturnError(false);
      axiosMock.shouldReturnData({ data: { id: 123456789 } });
    });

    it("makes the correct HTTP call", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post).toBeCalledWith(
        "https://api.example.com/v2/link-identity",
        {
          userEmail: eventMock.user.email,
          userEmailVerified: eventMock.user.email_verified,
          userPhone: eventMock.user.phone_number,
          userPhoneVerified: eventMock.user.phone_verified,
          userAuth0Id: eventMock.user.user_id,
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
      await onExecutePostLogin(eventMock, apiMock);
      expect(axiosMock.post).toHaveBeenLastCalledWith(
        `${eventMock.configuration.API_BASE_URL}/v2/link-identity`,
        {
          userEmail: eventMock.user.email,
          userEmailVerified: eventMock.user.email_verified,
          userPhone: eventMock.user.phone_number,
          userPhoneVerified: eventMock.user.phone_verified,
          userAuth0Id: eventMock.user.user_id,
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
      expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
        "https://your-claim-namespace/id",
        123456789
      );
    });

    it("sets the user metadata", async () => {
      await onExecutePostLogin(eventMock, apiMock);
      expect(apiMock.user.setAppMetadata).toBeCalledWith("yourMetadataNamespace", {
        id: 123456789,
      });
    });
  });
});
