const { faker } = require("@faker-js/faker");

jest.mock("axios");
const axiosMock = require("axios");

const { makeEventMock } = require("../__mocks__/event-post-login");
const { apiMock } = require("../__mocks__/api-post-login");

const { onExecutePostLogin, onContinuePostLogin } = require("./integration.action");

describe("Identity Verification", () => {
  let consoleLogMock, eventMock;

  beforeEach(() => {
    eventMock = makeEventMock();
    consoleLogMock = jest.spyOn(console, "log").mockImplementation();
  });

  afterEach(() => {
    consoleLogMock.mockRestore();
    axiosMock.mockRestore();
    jest.clearAllMocks();
  });

  describe("onExecutePostLogin", () => {
    describe("Configuration missing", () => {
      it("logs the issue", async () => {
        await onExecutePostLogin(eventMock, apiMock);
        expect(consoleLogMock).toBeCalledWith("Missing required configuration.");
      });
      it("does not redirect", async () => {
        await onExecutePostLogin(eventMock, apiMock);
        expect(apiMock.redirect.sendUserTo).not.toBeCalled();
      });

      describe("IDV optional", () => {
        it("does not block the login", async () => {
          await onExecutePostLogin(eventMock, apiMock);
          expect(apiMock.access.deny).not.toBeCalled();
        });
      });

      describe("IDV required", () => {
        it("blocks the login", async () => {
          eventMock.client.metadata.IDV_REQUIRED = "true";
          await onExecutePostLogin(eventMock, apiMock);
          expect(apiMock.access.deny).toBeCalled();
        });
      });
    });

    describe("IDV ID is stored", () => {
      beforeEach(async () => {
        eventMock.user.app_metadata = {
          yourMetadataNamespace: {
            id: faker.datatype.uuid(),
          },
        };
        eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
        eventMock.configuration.IDV_DOMAIN = faker.internet.domainName();
        await onExecutePostLogin(eventMock, apiMock);
      });

      it("sets the IDV id claim", async () => {
        expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
          "https://id-verification/id",
          eventMock.user.app_metadata.yourMetadataNamespace.id
        );
      });
    });

    describe("IDV not expired", () => {
      beforeEach(async () => {
        eventMock.user.app_metadata = {
          yourMetadataNamespace: {
            lastSuccessfulCheck: Math.floor(Date.now() / 1000),
          },
        };
        eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
        eventMock.configuration.IDV_DOMAIN = faker.internet.domainName();
        eventMock.configuration.IDV_EXPIRES_IN = `${30 * 24 * 60 * 60}`; // 30 days
        await onExecutePostLogin(eventMock, apiMock);
      });

      it("sets the IDV status claim", async () => {
        expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
          "https://id-verification/status",
          "valid"
        );
      });
      it("sets the IDV last check claim", async () => {
        expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
          "https://id-verification/last-check",
          eventMock.user.app_metadata.yourMetadataNamespace.lastSuccessfulCheck
        );
      });
      it("does not block the login", async () => {
        expect(apiMock.access.deny).not.toBeCalled();
      });
      it("does not redirect", async () => {
        expect(apiMock.redirect.sendUserTo).not.toBeCalled();
      });
    });

    describe("IDV expired or missing", () => {
      describe("Non-interactive login", () => {
        beforeEach(async () => {
          apiMock.redirect.canRedirect = jest.fn(() => false);
        });
        describe("IDV optional", () => {
          beforeEach(async () => {
            eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
            eventMock.configuration.IDV_DOMAIN = faker.internet.domainName();
            await onExecutePostLogin(eventMock, apiMock);
          });
          it("sets the IDV user ID claim", async () => {
            expect(apiMock.idToken.setCustomClaim).toBeCalledWith(
              "https://id-verification/status",
              "skipped"
            );
          });
          it("does not block the login", async () => {
            expect(apiMock.access.deny).not.toBeCalled();
          });
          it("does not redirect", async () => {
            expect(apiMock.redirect.sendUserTo).not.toBeCalled();
          });
        });
        describe("IDV required", () => {
          beforeEach(async () => {
            eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
            eventMock.configuration.IDV_DOMAIN = faker.internet.domainName();
            eventMock.client.metadata.IDV_REQUIRED = "true";
            await onExecutePostLogin(eventMock, apiMock);
          });

          it("blocks the login", async () => {
            expect(apiMock.access.deny).toBeCalled();
          });
        });
      });

      describe("Redirect", () => {
        let redirectToken;

        beforeEach(async () => {
          eventMock.user.app_metadata = {
            yourMetadataNamespace: {
              id: faker.datatype.uuid(),
            },
          };
          eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
          eventMock.configuration.IDV_DOMAIN = faker.internet.domainName();
          redirectToken = faker.datatype.uuid();
          apiMock.redirect.encodeToken = jest.fn(() => redirectToken);
          apiMock.redirect.canRedirect = jest.fn(() => true);
          await onExecutePostLogin(eventMock, apiMock);
        });

        it("sets the IDV user ID claim", async () => {
          expect(apiMock.redirect.encodeToken).toBeCalledWith({
            expiresInSeconds: 600,
            payload: {
              id: eventMock.user.app_metadata.yourMetadataNamespace.id,
            },
            secret: eventMock.secrets.TOKEN_SECRET,
          });
        });
        it("sends the user with a token", async () => {
          expect(apiMock.redirect.sendUserTo).toBeCalledWith(
            `https://${eventMock.configuration.IDV_DOMAIN}/id-verification`,
            {
              query: { token: redirectToken },
            }
          );
        });
      });
    });
  });

  describe("onContinuePostLogin", () => {
    describe("Invalid token", () => {
      beforeEach(async () => {
        eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
        apiMock.redirect.validateToken = jest.fn(() => {
          throw new Error();
        });
      });

      it("tries to validate the token", async () => {
        await onContinuePostLogin(eventMock, apiMock);
        expect(apiMock.redirect.validateToken).toBeCalledWith({
          secret: eventMock.secrets.TOKEN_SECRET,
          tokenParameterName: "token",
        });
      });
      it("logs the error", async () => {
        await onContinuePostLogin(eventMock, apiMock);
        expect(consoleLogMock).toBeCalled();
      });

      describe("IDV required", () => {
        it("blocks the login", async () => {
          eventMock.client.metadata.IDV_REQUIRED = "true";
          await onContinuePostLogin(eventMock, apiMock);
          expect(apiMock.access.deny).toBeCalled();
        });
      });

      describe("IDV optional", () => {
        it("does not block the login", async () => {
          await onContinuePostLogin(eventMock, apiMock);
          expect(apiMock.access.deny).not.toBeCalled();
        });
      });
    });

    describe("IDV status successful", () => {
      let idvUserId;
      let tokenIat;

      beforeEach(async () => {
        eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
        idvUserId = faker.datatype.uuid();
        tokenIat = faker.datatype.number();
        apiMock.redirect.validateToken = jest.fn(() => ({
          sub: idvUserId,
          status: "success",
          iat: tokenIat,
        }));
        await onContinuePostLogin(eventMock, apiMock);
      });

      it("sets app_metdata", async () => {
        expect(apiMock.user.setAppMetadata).toBeCalledWith("yourMetadataNamespace", {
          id: idvUserId,
          lastSuccessfulCheck: tokenIat,
        });
      });

      it("sets the IDV status claim", async () => {
        expect(apiMock.idToken.setCustomClaim).nthCalledWith(
          1,
          "https://id-verification/status",
          "success"
        );
      });
      it("sets the last check claim", async () => {
        expect(apiMock.idToken.setCustomClaim).toHaveBeenNthCalledWith(
          2,
          "https://id-verification/last-check",
          tokenIat
        );
      });
      it("sets the IDV user ID", async () => {
        expect(apiMock.idToken.setCustomClaim).nthCalledWith(
          3,
          "https://id-verification/id",
          idvUserId
        );
      });
    });

    describe("IDV status unsuccessful", () => {
      let idvUserId;
      let idvStatus;
      let tokenIat;

      beforeEach(async () => {
        eventMock.secrets.TOKEN_SECRET = faker.datatype.uuid();
        idvUserId = faker.datatype.uuid();
        idvStatus = faker.random.word();
        tokenIat = faker.datatype.number();
        apiMock.redirect.validateToken = jest.fn(() => ({
          sub: idvUserId,
          status: idvStatus,
          iat: tokenIat,
        }));
      });

      describe("IDV required", () => {
        it("blocks the login", async () => {
          eventMock.client.metadata.IDV_REQUIRED = "true";
          await onContinuePostLogin(eventMock, apiMock);
          expect(apiMock.access.deny).toBeCalled();
        });
      });

      describe("IDV optional", () => {
        beforeEach(async () => {
          await onContinuePostLogin(eventMock, apiMock);
        });

        it("sets the IDV status claim", async () => {
          expect(apiMock.idToken.setCustomClaim).toHaveBeenNthCalledWith(
            1,
            "https://id-verification/status",
            idvStatus
          );
        });

        it("sets the last check claim", async () => {
          expect(apiMock.idToken.setCustomClaim).toHaveBeenNthCalledWith(
            2,
            "https://id-verification/last-check",
            tokenIat
          );
        });

        it("sets the IDV user ID", async () => {
          expect(apiMock.idToken.setCustomClaim).toHaveBeenNthCalledWith(
            3,
            "https://id-verification/id",
            idvUserId
          );
        });
      });
    });
  });
});
