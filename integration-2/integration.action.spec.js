const { makeEventMock } = require("../__mocks__/event-post-login");
const { apiMock } = require("../__mocks__/api-post-login");

const { onExecutePostLogin } = require("./integration.action");

describe("Action integration", () => {
  let consoleLogMock;
  let eventMock;

  beforeEach(() => {
    consoleLogMock = jest.spyOn(console, "log").mockImplementation();
    eventMock = makeEventMock();
    apiMock.authentication = {
      challengeWithAny: jest.fn(),
      enrollWithAny: jest.fn(),
    };

    // Default valid request ID
    eventMock.request.query = { requestId: "validRequestId" };

    // Default values for configuration
    eventMock.configuration = {
      REGION: "Global",
      IDENTIFICATION_ERROR: "block_login",
      UNRECOGNIZED_VISITORID: "trigger_mfa",
      MAX_SUSPECT_SCORE: "15",
      BOT_DETECTION: "block_login",
      VPN_DETECTION: "allow_login",
      DENIED_MESSAGE: "Error logging in.",
    };

    // Default api key
    eventMock.secrets.FINGERPRINT_SECRET_API_KEY = "validApiKey";

    // Assume user is enrolled in MFA by default
    eventMock.user.multifactor = [{ type: "mfa" }];

    eventMock.user.app_metadata.com_fingerprint_skip = false;
    eventMock.user.app_metadata.com_fingerprint_currentVisitorId = "visitor123";
    eventMock.user.app_metadata.com_fingerprint_mfaNeeded = false;

    // Default authentication was successful
    eventMock.authentication = { methods: [{ name: "password" }] };
  });

  afterEach(() => {
    consoleLogMock.mockRestore();
    jest.clearAllMocks();
  });

  describe("onExecutePostLogin", () => {
    it("executes", async () => {
      expect(async () => {
        await onExecutePostLogin(eventMock, apiMock);
      }).not.toThrow();
    });

    describe("Configuration incorrect", () => {
      it("gracefully handles invalid configuration", async () => {
        eventMock.configuration.DENIED_MESSAGE = "invalidInput";
        eventMock.configuration.EXPOSE_VISITOR_IDS = "invalidInput";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalledWith();
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith("com_fingerprint_skip", true);
      });

      it("uses a default denial message if DENIED_MESSAGE is empty", async () => {
        eventMock.configuration.DENIED_MESSAGE = "";
        eventMock.user.app_metadata.com_fingerprint_currentVisitorId = null;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith("Error logging in.");
      });

      it("defaults EXPOSE_VISITOR_IDS to false if invalid value is provided", async () => {
        eventMock.configuration.EXPOSE_VISITOR_IDS = "invalid_value";
        eventMock.user.app_metadata.com_fingerprint_visitorIds = ["visitor123"];
        eventMock.user.app_metadata.com_fingerprint_currentVisitorId = "visitor123";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.idToken.setCustomClaim).not.toHaveBeenCalled();
      });
    });

    describe("Action error", () => {
      it("denies login if visitorId is missing and FP is not skipped", async () => {
        eventMock.user.app_metadata.com_fingerprint_currentVisitorId = null;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(eventMock.configuration.DENIED_MESSAGE);
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor123",
        ]);
      });

      it("handles missing app_metadata gracefully", async () => {
        delete eventMock.user.app_metadata;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith("Error logging in.");
      });
    });

    describe("Skips FP gracefully", () => {
      it("exits early when com_fingerprint_skip is true", async () => {
        eventMock.user.app_metadata.com_fingerprint_skip = true;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor123",
        ]);
      });
    });

    describe("MFA handled correctly", () => {
      it("denies login if MFA was required but not completed successfully", async () => {
        eventMock.user.app_metadata.com_fingerprint_mfaNeeded = true;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(eventMock.configuration.DENIED_MESSAGE);
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor123",
        ]);
      });

      it("allows login and updates visitorId if MFA was completed successfully", async () => {
        eventMock.user.app_metadata.com_fingerprint_mfaNeeded = true;
        eventMock.authentication.methods.push({ name: "mfa" });

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor123",
        ]);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
      });

      it("denies login when MFA is required but no authentication methods exist", async () => {
        eventMock.user.app_metadata.com_fingerprint_mfaNeeded = true;
        eventMock.authentication.methods = [];

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith("Error logging in.");
      });
    });

    describe("Visitor ID updates", () => {
      it("adds a new visitorId to the app metadata if not already present", async () => {
        eventMock.user.app_metadata.com_fingerprint_visitorIds = ["visitor456"];
        eventMock.user.app_metadata.com_fingerprint_currentVisitorId = "visitor123";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor456",
          "visitor123",
        ]);
      });

      it("does not duplicate visitorId if it already exists in app metadata", async () => {
        eventMock.user.app_metadata.com_fingerprint_visitorIds = ["visitor123"];
        eventMock.user.app_metadata.com_fingerprint_currentVisitorId = "visitor123";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith("com_fingerprint_visitorIds", [
          "visitor123",
          "visitor123",
        ]);
      });
    });

    describe("Custom claims", () => {
      it("exposes visitor IDs as a custom claim if EXPOSE_VISITOR_IDS is true", async () => {
        eventMock.configuration.EXPOSE_VISITOR_IDS = "true";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.idToken.setCustomClaim).toHaveBeenCalledWith(
          "https://fingerprint.com/visitorIds",
          ["visitor123"]
        );
      });

      it("does not expose visitor IDs as a custom claim if EXPOSE_VISITOR_IDS is false", async () => {
        eventMock.configuration.EXPOSE_VISITOR_IDS = false;

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.idToken.setCustomClaim).not.toHaveBeenCalled();
      });
    });
  });
});
