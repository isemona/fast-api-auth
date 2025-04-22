# FastAPI Quickstart Sample Code for Integrating with Okta

This repository contains a sample of protecting API endpoints in a custom resource server using a custom authorization server in [Okta](https://www.okta.com/). The can be paired with a Single Page Frontend such as [Okta React Sample](https://github.com/okta-samples/okta-react-sample?tab=readme-ov-file).

The sample uses the [Authlib](https://docs.authlib.org/en/latest/#). Read more about getting started with Okta and authentication best practices on the [Okta Developer Portal](https://developer.okta.com).

This code sample demonstrates
* Configuring Okta
* Protecting FastAPI routes
* Verifying the JWT

## Getting started

To run this example, run the following commands:

```shell
git clone -b oauth2-demo https://github.com/isemona/fast-api-auth.git
pip install requirements.txt
```

## Create an OIDC organization in Okta

Create a free Okta Developer account to create your Okta organization. You can do this through the [Okta CLI](https://cli.okta.com/) or through the [Okta Developer admin](https://developer.okta.com) dashboard.

When using the Okta CLI run the following command:

```shell
okta register
```

Ensure that your default custom authorization server has an access policy. Add an access policy if it's not there. See [Create access polices](https://help.okta.com/okta_help.htm?type=oie&id=ext-create-access-policies).

You will need your Okta domain and Audience.

Update .env with your Okta settings.

```
OKTA_CLIENT_ID="your-client-id"
OKTA_ISSUER="https://your-dev-org.okta.com/oauth2/default"
OKTA_AUDIENCE="name-of-the-api-resource"
USE_INTROSPECTION=false
```

Start the app by running

```
uvicorn main:app --reload
```

Use your favorite HTTP Client to call the API. For authenticated calls, follow the steps in [Send a request to your API endpoint using Postman]() of the quick start.

## Helpful resources

* [Learn about Authentication, OAuth 2.0, and OpenID Connect](https://developer.okta.com/docs/concepts/)
* [Get started with Express](https://expressjs.com/)


