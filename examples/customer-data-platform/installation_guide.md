This guide walks you through how to set up and send user data to a CDP Service.

## Prerequisites

1. An Auth0 account and tenant. [Sign up for free here](https://auth0.com/signup).
2. An CDP Service

## Set up the CDP Service

The CDP Service needs to maintain an endpoint `/v2/events` on the base URL provided via the configuration steps below. This endpoint needs to validate an API key provided in the configuration and return a 2xx successful status code.

## Add the Auth0 Action

**Note:** Once the Action is successfully deployed, all logins for your tenant will be processed by this integration. Make sure this Action is installed and [verified on a test tenant](https://auth0.com/docs/get-started/auth0-overview/create-tenants/set-up-multiple-environments) before activating the integration in production.

1. Select **Add Integration** (at the top of this page).
1. Read the necessary access requirements and click **Continue**.
1. Configure the integration using the following fields:
   * **CDP API Key** - The API key used to call the CDP service.
   * **Service Tenant Domain** - The base URL of the CDP service. Defaults to `https://api.example.com/`.
1. Click **Create** to add the integration to your Library.
1. Click the **Add to flow** link on the pop-up that appears.
1. Drag the Action into the desired location in the flow.
1. Click **Apply Changes**.

## Results

The result of this Action is a POST to the API endpoint. A failing or misconfigured Action will report problems in the log but not fail login for any reason.
