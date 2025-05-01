const { makeEventMock } = require("../__mocks__/event-post-login");
const { apiMock } = require("../__mocks__/api-post-login");

// Mock the Fingerprint library
jest.mock("@fingerprintjs/fingerprintjs-pro-server-api", () => ({
  FingerprintJsServerApiClient: jest
    .fn()
    .mockImplementation(({ region, apiKey }) => ({
      getEvent: jest.fn().mockImplementation((requestId) => {
        if (apiKey !== "validApiKey") {
          return Promise.reject(new Error("Invalid API key"));
        }

        if (!["Global", "EU", "AP"].includes(region)) {
          return Promise.reject(new Error("Invalid region"));
        }

        if (requestId === "validRequestId") {
          return Promise.resolve({
            products: {
              identification: {
                data: { visitorId: "visitor123", suspect: { score: 5 } },
              },
              botd: { data: { bot: { result: "notDetected" } } },
              vpn: { data: { result: false } },
            },
          });
        }
        if (requestId === "invalidRequestId") {
          return Promise.reject(new Error("Invalid request ID"));
        }
        if (requestId === "validRequestIdBot") {
          return Promise.resolve({
            products: {
              identification: {
                data: { visitorId: "visitor123", suspect: { score: 5 } },
              },
              botd: { data: { bot: { result: "good" } } },
              vpn: { data: { result: false } },
            },
          });
        }
        if (requestId === "validRequestIdVpn") {
          return Promise.resolve({
            products: {
              identification: {
                data: { visitorId: "visitor123", suspect: { score: 5 } },
              },
              botd: { data: { bot: { result: "notDetected" } } },
              vpn: { data: { result: true } },
            },
          });
        }
        if (requestId === "validRequestIdSuspect") {
          return Promise.resolve({
            products: {
              identification: {
                data: { visitorId: "visitor123", suspect: { score: 20 } },
              },
              botd: { data: { bot: { result: "notDetected" } } },
              vpn: { data: { result: false } },
            },
          });
        }
        return Promise.reject(new Error("Unexpected error"));
      }),
    })),
  Region: { Global: "Global", EU: "EU", AP: "AP" },
  RequestError: class RequestError extends Error {
    constructor(message) {
      super(message);
      this.responseBody = {};
      this.response = {};
      this.statusCode = 400;
    }
  },
}));

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
      AVAILABLE_MFA: "otp,push-notification",
    };

    // Default api key
    eventMock.secrets.FINGERPRINT_SECRET_API_KEY = "validApiKey";

    // Assume user is enrolled in MFA by default
    eventMock.user.enrolledFactors = [{ type: "otp" }];
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
        eventMock.configuration.REGION = "invalidInput";
        eventMock.configuration.IDENTIFICATION_ERROR = "invalidInput";
        eventMock.configuration.UNRECOGNIZED_VISITORID = "invalidInput";
        eventMock.configuration.MAX_SUSPECT_SCORE = "invalidInput";
        eventMock.configuration.BOT_DETECTION = "invalidInput";
        eventMock.configuration.VPN_DETECTION = "invalidInput";
        eventMock.configuration.DENIED_MESSAGE = "invalidInput";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalledWith();
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });
    });

    describe("Identification error", () => {
      it("denies login if requestId is missing and IDENTIFICATION_ERROR is 'block_login'", async () => {
        eventMock.request.query = {};
        eventMock.configuration.IDENTIFICATION_ERROR = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(
          eventMock.configuration.DENIED_MESSAGE
        );
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("allows login if requestId is missing and IDENTIFICATION_ERROR is 'allow_login'", async () => {
        eventMock.request.query = {};
        eventMock.configuration.IDENTIFICATION_ERROR = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("denies login if requestId is invalid and IDENTIFICATION_ERROR is 'block_login'", async () => {
        eventMock.request.query = { requestId: "invalidRequestId" };
        eventMock.configuration.IDENTIFICATION_ERROR = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(
          eventMock.configuration.DENIED_MESSAGE
        );
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("allows login if requestId is invalid and IDENTIFICATION_ERROR is 'allow_login'", async () => {
        eventMock.request.query = { requestId: "invalidRequestId" };
        eventMock.configuration.IDENTIFICATION_ERROR = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("skips Fingerprint checks if invalid API key and IDENTIFICATION_ERROR is 'allow_login'", async () => {
        eventMock.secrets.FINGERPRINT_SECRET_API_KEY = null;
        eventMock.configuration.IDENTIFICATION_ERROR = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("denies login if invalid API key and IDENTIFICATION_ERROR is 'block_login'", async () => {
        eventMock.secrets.FINGERPRINT_SECRET_API_KEY = null;
        eventMock.configuration.IDENTIFICATION_ERROR = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalled();
      });
    });

    describe("Bot activity is detected", () => {
      it("denies login for detected bot when BOT_DETECTION is 'block_login'", async () => {
        eventMock.request.query = { requestId: "validRequestIdBot" };
        eventMock.configuration.BOT_DETECTION = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(
          eventMock.configuration.DENIED_MESSAGE
        );
      });

      it("triggers MFA for detected bot when BOT_DETECTION is 'trigger_mfa'", async () => {
        eventMock.request.query = { requestId: "validRequestIdBot" };
        eventMock.configuration.BOT_DETECTION = "trigger_mfa";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(true);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });

      it("allows login for detected bot when BOT_DETECTION is 'allow_login'", async () => {
        eventMock.request.query = { requestId: "validRequestIdBot" };
        eventMock.configuration.BOT_DETECTION = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });
    });

    describe("VPN use is detected", () => {
      it("denies login for detected VPN when VPN_DETECTION is 'block_login'", async () => {
        eventMock.request.query = { requestId: "validRequestIdVpn" };
        eventMock.configuration.VPN_DETECTION = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).toHaveBeenCalledWith(
          eventMock.configuration.DENIED_MESSAGE
        );
      });

      it("triggers MFA for detected VPN when VPN_DETECTION is 'trigger_mfa'", async () => {
        eventMock.request.query = { requestId: "validRequestIdVpn" };
        eventMock.configuration.VPN_DETECTION = "trigger_mfa";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(true);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });

      it("allows login for detected VPN when VPN_DETECTION is 'allow_login'", async () => {
        eventMock.request.query = { requestId: "validRequestIdVpn" };
        eventMock.configuration.VPN_DETECTION = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });
    });

    describe("Suspicious visitors", () => {
      it("triggers MFA if Suspect Score exceeds MAX_SUSPECT_SCORE", async () => {
        eventMock.request.query = { requestId: "validRequestIdSuspect" };
        eventMock.configuration.MAX_SUSPECT_SCORE = "15";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(true);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
      });

      it("doesn't trigger MFA if MAX_SUSPECT_SCORE is -1", async () => {
        eventMock.request.query = { requestId: "validRequestIdSuspect" };
        eventMock.configuration.MAX_SUSPECT_SCORE = "-1";
        eventMock.user.app_metadata = {
          com_fingerprint_visitorIds: ["visitor123"],
        };
        eventMock.user.enrolledFactors = [{ type: "otp" }];

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(false);
        expect(apiMock.user.setAppMetadata).not.toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
      });

      it("triggers MFA if visitorId is recognized but MAX_SUSPECT_SCORE is exceeded", async () => {
        eventMock.request.query = { requestId: "validRequestIdSuspect" };
        eventMock.configuration.MAX_SUSPECT_SCORE = "15";
        eventMock.user.app_metadata = {
          com_fingerprint_visitorIds: ["visitor123"],
        };

        await onExecutePostLogin(eventMock, apiMock);
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(true);
      });
    });

    describe("Unrecognized device", () => {
      it("triggers MFA if visitorId is unrecognized and UNRECOGNIZED_VISITORID is 'trigger_mfa'", async () => {
        eventMock.configuration.UNRECOGNIZED_VISITORID = "trigger_mfa";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(
          apiMock.authentication.challengeWithAny.mock.calls.length > 0 ||
            apiMock.authentication.enrollWithAny.mock.calls.length > 0
        ).toBe(true);
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });

      it("allows login if visitorId is unrecognized and UNRECOGNIZED_VISITORID is 'allow_login'", async () => {
        eventMock.configuration.UNRECOGNIZED_VISITORID = "allow_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_currentVisitorId",
          "visitor123"
        );
      });
    });

    describe("Recognized visitor", () => {
      it("allows login without MFA if visitorId is recognized", async () => {
        eventMock.configuration.UNRECOGNIZED_VISITORID = "allow_login";
        eventMock.user.app_metadata = {
          com_fingerprint_visitorIds: ["visitor123"],
        };

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.access.deny).not.toHaveBeenCalled();
        expect(apiMock.authentication.challengeWithAny).not.toHaveBeenCalled();
      });
    });

    describe("Not enrolled in MFA", () => {
      it("enrolls MFA when passes all checks but no MFA is enrolled", async () => {
        eventMock.user.enrolledFactors = [];

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_mfaNeeded",
          true
        );
      });
    });

    describe("AVAILABLE_MFA configuration", () => {
      beforeEach(() => {
        eventMock.user.enrolledFactors = [];
      });

      it("enrolls user with specified MFA methods when AVAILABLE_MFA is provided", async () => {
        eventMock.configuration.AVAILABLE_MFA = "otp,push-notification";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).toHaveBeenCalledWith([
          { type: "otp" },
          { type: "push-notification" },
        ]);
      });

      it("doesn't enroll user if user is already enrolled in MFA", async () => {
        eventMock.user.enrolledFactors = [{ type: "otp" }];

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).not.toHaveBeenCalled();
      });

      it("handles single MFA method correctly", async () => {
        eventMock.configuration.AVAILABLE_MFA = "otp";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).toHaveBeenCalledWith([
          { type: "otp" },
        ]);
      });

      it("handles empty AVAILABLE_MFA configuration by following the IDENTIFICATION_ERROR configuration", async () => {
        eventMock.configuration.AVAILABLE_MFA = "";
        eventMock.configuration.IDENTIFICATION_ERROR = "block_login";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).not.toHaveBeenCalled();
        expect(apiMock.user.setAppMetadata).toHaveBeenCalledWith(
          "com_fingerprint_skip",
          true
        );
      });

      it("handles whitespace in AVAILABLE_MFA configuration", async () => {
        eventMock.configuration.AVAILABLE_MFA = "  otp  ,  push-notification  ";

        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.authentication.enrollWithAny).toHaveBeenCalledWith([
          { type: "otp" },
          { type: "push-notification" },
        ]);
      });
    });
  });
});
