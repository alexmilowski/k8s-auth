# k8s-auth
A simple authorization proxy for forwarding principals via JWT bearer tokens.

## Overview

The purpose of this service is a simple proxy that authenticates via an [OpenID Connect](https://openid.net/connect/) service conforming to OAuth 2.0. The service
tracks the authentication of the user and forwards the request with a bearer
authentication token containing a JWT token. The intent is to identify the
authenticated principal for systems like [istio](http://istio.io).

## Simple Usage

With a client id, secret, and endpoint for your service:

```
python -m app {client_id} {secret} --endpoint {service_url}
```

If your application has a public-facing URL, identify it via the `--redirect-uri` parameter. This must be the same URI configured with your authentication provider.

The authentication provider can be set via the `--auth-provider` parameter and defaults to Google.

The token provider can be set via the `--token-provider` parameter and defaults to Google.

## Setup via Google Cloud

Under the "APIs & Services > Credentials" you can:

 1. Choose "Create credentials > OAuth client_secret ID"
 1. Choose "Web Application"
 1. Give the application a name.
 1. Add the appropriate "Authorized redirect URIs" for your service deployment (or test). This must match exactly the parameter use when you run the service (e.g., the `--redirect-uri` value).
 1. Choose "Create" and record the client id and secret to use when running the proxy.

## Current Docker Image

```
alexmilowski/k8s-auth:0017
```
