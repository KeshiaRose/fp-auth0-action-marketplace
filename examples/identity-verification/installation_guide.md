This guide walks you through how to set up and activate identity verification using Identity Verification Service.

## Prerequisites

1. An Auth0 account and tenant. [Sign up for free here](https://auth0.com/signup).
2. An Identity Verification Service

## Set up the Identity Verification Service

The Identity Verification Service needs to maintain an endpoint `/id-verfication` on the domain provided via the configuration steps below. This endpoint needs to verify and decode the redirect token, complete the ID verification, then redirect back to Auth0 with the same `state` value found in URL parameters. 

## Add the Auth0 Action

**Note:** Once the Action is successfully deployed, all logins for your tenant will be processed by this integration. Make sure this Action is installed and [verified on a test tenant](https://auth0.com/docs/get-started/auth0-overview/create-tenants/set-up-multiple-environments) before activating the integration in production.

1. Select **Add Integration** (at the top of this page).
1. Read the necessary access requirements and click **Continue**.
1. Configure the integration using the following fields:
   * **Token Secret** - The secret used to sign the token sent to the identity verification service.
   * **Service Tenant Domain** - The domain where the identity verification service is running
   * **Verification Expires In Seconds** - Number of seconds that a successful identity verification is considered valid.
1. Click **Create** to add the integration to your Library.
1. Click the **Add to flow** link on the pop-up that appears.
1. Drag the Action into the desired location in the flow.
1. Click **Apply Changes**.

## Applications Requiring Identity Verification (optional)

If you have a sensitive application that requires identity verification for every login, you can set an Application metadata value in Auth0 to enforce this check. Follow [the instructions here](https://auth0.com/docs/get-started/applications/configure-application-metadata) to set a metadata entry with a **Key** of `IDV_REQUIRED` set to a **Value** of `true` and all logins for that Application will be protected by this check.

## Results

The result of this Action depends on the configuration and the outcome of the identity verification. Applications requesting login should look for the following claims in the returned ID token:

- `https://id-verification/status` - This claim will contain the status of the identity verification. A status of `valid` means it completed successfully. If this claim is missing or contains any other status means the verification failed or was not completed.
- `https://id-verification/last-check` - If present, this claim will contain the date and time of the last identity verification check 
- `https://id-verification/id` - If present, this claim will contain the user ID from the verification service.

If identity verification is required and cannot be completed successfully, the login will fail with one of the following error codes in the `error_description` URL parameter sent to the requesting application's callback URL:

- `idv_verification_failed` - The identity verification failed.
- `idv_interaction_required` - The identity verification could not be completed because it requires user interaction on a non-interactive login flow (like refresh token exchange).
- `idv_configuration_error` - The identity verification could not be attempted because the Action is not correctly configured.
