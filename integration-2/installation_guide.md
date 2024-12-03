# Auth0 Fingerprint Integration

> Note: This is Part 2 of a 2-part Action integration. To ensure the integration works correctly, you must install and configure both actions in the correct order. The first action must be the first action in your post-login flow. The actions will not function fully without correct installation. The instructions below cover both actions.

This integration enhances your Auth0 login flows with Fingerprint's visitor identification. Fingerprint provides a unique identifier for each browser or device, along with actionable insights to help prevent fraud and improve user experiences.

Fingerprint Identification collects over 100 attributes from a user's browser or device to generate stable visitor identifiers that remain consistent even after browser updates or cookie clearance. Fingerprint Smart Signals provide additional details, such as VPN usage, browser tampering, or bot activity. This data strengthens your Auth0 login flows by enabling the detection of suspicious behavior even when the user has the right credentials.

To see a full walkthrough and breakdown of how these Action scripts work, check out our [Fingerprint + Auth0 tutorial](https://fingerprint.com/blog/iam-integration-prevent-account-takeover/).

## Prerequisites

1. An Auth0 account and tenant. [Sign up for free](https://auth0.com/signup).
1. A Fingerprint account. [Sign up for a free trial](https://dashboard.fingerprint.com/signup/).

## 1. Add Fingerprint to your application

To identify your visitors, add the Fingerprint device intelligence client agent to your website or mobile application:

1. Go to the [Fingerprint dashboard](https://dashboard.fingerprint.com/).
1. Navigate to **[SDKs & integrations](https://dashboard.fingerprint.com/integrations)** to explore the available web and mobile libraries and find the easiest way to install Fingerprint for your app.
1. You can [load](https://dev.fingerprint.com/docs/install-the-javascript-agent) the client agent directly in vanilla JavaScript or use a type-safe [SDK](https://dev.fingerprint.com/docs/frontend-libraries) for your favorite framework.

Here is a [React](https://github.com/fingerprintjs/fingerprintjs-pro-react) example:

```jsx
import { FpjsProvider, useVisitorData } from "@fingerprintjs/fingerprintjs-pro-react";

const App = () => (
  <FpjsProvider
    loadOptions={{
      apiKey: "PUBLIC_API_KEY",
      endpoint: [
        // "https://metrics.yourwebsite.com",
        FingerprintJSPro.defaultEndpoint,
      ],
      scriptUrlPattern: [
        // "https://metrics.yourwebsite.com/web/v<version>/<apiKey>/loader_v<loaderVersion>.js",
        FingerprintJSPro.defaultScriptUrlPattern,
      ],
      // region: "eu"
    }}
  >
    <VisitorData />
  </FpjsProvider>
);

const VisitorData = () => {
  const { data } = useVisitorData();
  return (
    <div>
      Visitor ID: ${data?.visitorId}, Request ID: ${data?.requestId}
    </div>
  );
};
```

The returned `visitorId` is a unique and stable identifier of your visitor. The `requestId` is the unique identifier for a specific identification event.

1. All the code snippets on the Integrations page already include your public API key, but you can also find it on the **[API Keys](https://dashboard.fingerprint.com/api-keys)** page.
1. After making a successful identification request, you should see your identification event in the Fingerprint [dashboard](https://dashboard.fingerprint.com/) on the **[Identification](https://dashboard.fingerprint.com/events)** page.

Consult the Fingerprint [Quick Start Guide](https://dev.fingerprint.com/docs/quick-start-guide) or contact [Fingerprint support](https://fingerprint.com/support/) if you have any questions.

> Note: For production deployments, we recommend routing requests to Fingerprint APIs through your own domain. This prevents ad blockers from disrupting identification requests and improves accuracy. We offer a variety of proxy integration options, see [Protecting your JavaScript agent from ad blockers](https://dev.fingerprint.com/docs/protecting-the-javascript-agent-from-adblockers) for more details.

## 2. Send Fingerprint identification results to Auth0

Modify your Auth0 implementation to send the Fingerprint identification results as additional *authorization parameters*.

For most JavaScript-based Auth0 SDKs, you can pass the `requestId` and `visitorId` as custom `authorizationParams` into the `loginWithRedirect` function. Here is an example using the [Auth0 React SDK](https://auth0.com/docs/libraries/auth0-react):

```jsx
import { useVisitorData } from "@fingerprintjs/fingerprintjs-pro-react";
import { useAuth0 } from "@auth0/auth0-react";

const Login = () => {
  const { loginWithRedirect } = useAuth0();
  const { data } = useVisitorData();

  return (
    <Button
      onClick={() =>
        loginWithRedirect({
          authorizationParams: {
            visitorId: data?.visitorId,
            requestId: data?.requestId,
          },
        })
      }
    >
      Log in
    </Button>
  );
};
```

If you are using a redirect-based Auth0 SDK designed for server-rendered applications, you will need to:

1. Pass the `requestId` and `visitorId` as query parameters to the login route. An example using [Auth0 Next SDK](https://auth0.com/docs/quickstart/webapp/nextjs/01-login):

   ```jsx
   import { useVisitorData } from "@fingerprintjs/fingerprintjs-pro-react";

   const LoginLink = () => {
     const { data } = useVisitorData();

     return (
       <AnchorLink
         href={`/api/auth/login?visitorId=${data?.visitorId}&requestId=${data?.requestId}`}
       >
         Log in
       </AnchorLink>
     );
   };
   ```

1. Customize the login route handler to pass the query parameters to Auth0 as `authorizationParams`. An example using the [Auth0 Next SDK](https://auth0.com/docs/quickstart/webapp/nextjs/01-login):

   ```jsx
   // src/pages/api/auth/[...auth0].js

   import { handleAuth, handleLogin } from "@auth0/nextjs-auth0";

   export default handleAuth({
     async login(req, res) {
       // Pass visitorId as custom parameter to login
       await handleLogin(req, res, {
         authorizationParams: {
           visitorId: req.query.visitorId,
           requestId: req.query.requestId,
         },
       });
     },
   });
   ```

Your implementation details will vary depending on how you integrate Auth0 with your application. Reach out to Auth0 support if you have any questions about passing custom authorization parameters.

We recommend using the Fingerprint integration with the New Universal Login as it's server-side rendered. Using it with the Classic Universal Login will result in the additional parameters being visible to the end user.

## Add the Auth0 Actions

**Note:** Once both Actions are successfully deployed, all logins for your tenant will be processed by these integrations. Before activating the integrations in production, [install and verify the Actions on a test tenant](https://auth0.com/docs/get-started/auth0-overview/create-tenants/set-up-multiple-environments).

1. Select **Add Integration** (at the top of this page).
1. Read the necessary access requirements, and select **Continue**.
1. Configure the integration using the following fields:
   * FINGERPRINT_SECRET_API_KEY: Enter your secret Fingerprint Server API key, which is used for server-to-server requests. This key can be generated in the **[Fingerprint Dashboard](https://dashboard.fingerprint.com/api-keys)**.
   * REGION: Select the region where your Fingerprint application stores data; options include Global (US), EU, or Asia, with a default of US.
   * IDENTIFICATION_ERROR: Choose how to handle missing or spoofed request IDs; options include blocking the login, triggering MFA (default), or allowing login (not recommended).
   * UNRECOGNIZED_VISITORID: Define the behavior for logins from new devices with unrecognized visitor IDs, either by triggering MFA (default) or allowing login.
   * MAX_SUSPECT_SCORE: Set a threshold for triggering MFA based on the Suspect Score. Set to -1 to disable this feature.
   * BOT_DETECTION: Decide how to handle logins from detected bots, with options to block login (default), trigger MFA, or allow login.
   * VPN_DETECTION: Configure how VPN usage is handled, with options to allow login (default), trigger MFA, or block login.
   * DENIED_MESSAGE: Provide a generic error message for denied logins.
1. Add the integration to your Library by selecting **Create**.
1. In the modal that appears, select the **Add to flow** link.
1. Drag the Action into the desired location in the flow.
1. Select **Apply Changes**.
1. Go back to the listing for part 2 of this action.
1. Select **Add Integration** (at the top of this page).
1. Read the necessary access requirements, and select **Continue**.
1. Configure the integration using the following fields:
   * DENIED_MESSAGE: Provide a generic error message for denied logins.
   * EXPOSE_VISITOR_IDS: Determine whether the list of visitor IDs should be included as a custom claim in the ID token.
1. Add the integration to your Library by selecting **Create**.
1. In the modal that appears, select the **Add to flow** link.
1. Drag the Action **directly after** the first Fingerprint action in the flow.
1. Select **Apply Changes**.

## Results

Once the Actions are configured and deployed, they integrate Fingerprint device recognition and risk-based security checks into your login flow, adapting to the configuration options you've set. During the login process, the Actions validate the identification result against the Fingerprint Server API. If the identification result is invalid, missing, or fails to match the identification event, the Actions will follow the behavior defined in the `IDENTIFICATION_ERROR` option (e.g., block login, trigger MFA, or allow login). You must have at least one form of MFA enabled.

The login flow also enforces the settings for handling new or unrecognized devices. If a visitor ID is not associated with the user's account, the Actions will either trigger MFA or allow the login, based on your `UNRECOGNIZED_VISITORID` configuration. Similarly, bot activity and VPN usage are monitored and managed per the `BOT_DETECTION` and `VPN_DETECTION` options, respectively. For instance, you can choose to block logins, prompt for MFA, or allow access under these conditions.

Additionally, the `MAX_SUSPECT_SCORE` threshold, if enabled, helps detect suspicious behavior. If a user's Suspect Score exceeds the threshold, MFA is automatically triggered to verify their identity.

Logins that are denied for any reason will display the `DENIED_MESSAGE`, which can be customized to avoid exposing specific denial reasons.

After processing, the Actions store the visitor ID in a list of recognized visitor IDs in the user's app metadata. This allows the Actions to retrieve and verify the user's trusted devices during future logins. The visitor ID is only added to the list upon successful completion of all configured security checks, including MFA if required. If you enable the `EXPOSE_VISITOR_IDS` option to expose visitor IDs as a custom claim, a `https://fingerprint.com/visitorIds` claim will be included in the ID token and accessible from your app.

## Troubleshooting

For more information about Fingerprint, visit our [website](https://fingerprint.com/) or check out the [documentation](https://dev.fingerprint.com). If you have any questions, reach out to our [support team](https://fingerprint.com/support/) for help.
