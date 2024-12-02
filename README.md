# Post Login Action Integration Template

This template is used to create Action Integrations in the Login flow. The Login Flow runs when a user logs in to any application in an Auth0 tenant.

## Documentation

- [Login flow documentation](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow)
- [Event object documentation](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/event-object)
- [API object documentation](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow/api-object)
- [Action Integrations documentation](https://auth0.com/docs/customize/integrations/marketplace-partners/actions-integrations-for-partners)
- [Coding guidelines](https://auth0.com/docs/customize/actions/action-coding-guidelines)

## Getting started

This repo contains all the files required to create an integration that our mutual customers can install. In the `integration` folder you'll find the following files:

- [configuration.json](#configurationjson)
- [installation_guide.md](#installationguidemd)
- [integration.action.js](#integrationactionjs)
- [integration.action.spec.js](#integrationactionspecjs)

### `configuration.json`

This file defines secrets (values are encrypted at rest), configuration (values can be seen and edited), and dependencies used when the Action code is run during a flow.

This file expects 3 keys, any of which can be an empty array:

- `secrets` - array of values that need encryption (API keys, signing keys, etc.).
- `configuration` - array of values that are stored and edited in plain text (URLs, labels, etc.).
- `dependencies` - Node.js dependencies used during runtime

Here is a valid example `configuration.json` file. Details are explained below

```json
{
  "secrets": [
    {
      "name": "ALL_CAPS_UNDERSCORE_SECRET",
      "label": "Field Label",
      "description": "Field description",
      "default_value": "optional default value to use",
      "deploy_value": "optional deployment value to use"
    }
  ],
  "configuration": [
    {
      "name": "ALL_CAPS_UNDERSCORE_CONFIG",
      "label": "Field Label",
      "description": "Field description",
      "default_value": "optional default value to use",
      "deploy_value": "optional deployment value to use",
      "options": [
        {
          "value": "option_1_value",
          "label": "Option 1 Label"
        },
        {
          "value": "option_2_value",
          "label": "Option 2 Label"
        }
      ]
    }
  ],
  "dependencies": [ 
    {
      "name": "package-name",
      "version": "1.0.0" 
    }
  ]
}
```

#### Secrets and Configuration

**Note:** If you are building and testing your Action directly in the dashboard, you will need to add all configuration as secrets and use `event.secrets` in your code before saving the Action. If you use our [deployment tools](#build-and-test-your-integration), you can use `event.configuration` in your code and this substitution will be done automatically during deployment.

These are arrays of objects with the following shape:

- `name`: Required; the name used in the code. This value should be `ALL_CAPS_UNDERSCORE`.
- `label`: Required; the field label that will be used in the Auth0 dashboard.
- `description`: Required; the field description that will be used in the Auth0 dashboard.
- `default_value`: Optional; the default value to use when the Action is first installed.
- `deploy_value`: Optional; the value to use when creating or updating an Action using the deploy scripts explained below
- `options`: Optional; an array of option objects to use for a `configuration` select field:
    - `value`: Required; the value of the option if selected
    - `label`: Required; the text shown in the UI for this option

#### Dependencies

This should be an array of objects with the following shape:

- `name`: name of the package as listed on https://npmjs.com/
- `version`: pinned version of the package (no ranges)

### `installation_guide.md`

This file contains the Markdown-formatted instructions that tenant admins will use to install and configure your integration. This file has a number of `TODO` items that indicate what needs to be added. Your guide should retain the same general format and provided Auth0 installation steps.

### `integration.action.js`

This is the code that will run on a customer's tenant on all logins. See the [Login flow documentation](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow) for information on the data contained in the `event` object and the methods available on the `api` object.

### `integration.action.spec.js`

This is the [Jest](https://jestjs.io/docs/using-matchers) unit test suite that will run against your completed Action code. Add tests for success and failure paths.

## Recommended Testing

Before submitting your integration, it's crucial to ensure that it's built and tested thoroughly. We've provided a set of scripts in the Makefile to assist you in this process. These scripts will help you build, test, and deploy a high-quality integration. It's recommended to develop your Action locally and utilize the commands below for linting, testing, and deployment.

The commands below require Docker to be installed and running on your local machine (though no direct Docker experience is necessary). Download and install Docker [using these steps for your operating system](https://docs.docker.com/get-docker/). 

**Please note:** When you run the tests, they are executed against the **Current Active LTS of Node.js**.

* `make test` - this will run the Jest spec file explained above, along with a few other integrity checks. This check is run in a GitHub Action located in `.github/workflows/test.yaml`.
* `make lint` - this will check and format your JS code according to our recommendations. This check is run in a GitHub Action located in `.github/workflows/lint.yaml`.
* `make deploy_init` - use this command to initialize deployments to a test tenant. You will need to [create a machine-to-machine application](https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps) authorized for the Management API with permissions `read:actions`, `update:actions`, `delete:actions`, and `create:actions`.
* `make deploy_get_token` - use this command after `deploy_init` to generate an access token
* `make deploy_create` - use this command to create a new Action based on the current integration files. If this successfully completes, you will see a URL in your terminal that will allow you to deploy and add the Action to a flow
* `make deploy_update` - use this command to update the created Action based on the current integration files.
* `make deploy_delete` - use this command to remove the Action from your tenant completely.

## Submit for review

When your integration has been written and tested, it's time to submit it for review.

1. Change `event.secrets` to `event.configuration` for all applicable keys (see above)
1. Replace the `media/256x256-logo.png` file with an image of the same size and format (256 pixel square on a transparent background)
1. If you provided value-proposition columns and would like to include images, replace the `media/460x260-column-*.png` files with images of the same size and format; otherwise, delete these images before submitting
1. Run `make zip` in the root of the integration package and upload the resulting archive to the Jira ticket.

If you have any questions or problems with this, please reply back on the support ticket!

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://auth0.com/docs/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional [username/password databases](https://auth0.com/docs/connections/database/custom-db).
* Add support for [linking different user accounts](https://auth0.com/docs/link-accounts) with the same user.
* Support for generating signed [JSON Web Tokens](https://auth0.com/docs/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when, and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://auth0.com/docs/rules/current).

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file in this repo for more info.
