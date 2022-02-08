![CI](https://img.shields.io/github/workflow/status/jrakotoharisoa/remix-auth-okta/CI?style=flat-square)
![npm](https://img.shields.io/npm/v/remix-auth-okta?style=flat-square)
# OktaStrategy

The Okta strategy is used to authenticate users against an okta account. It extends the OAuth2Strategy.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

<!-- If it doesn't support one runtime, explain here why -->

## How to use

### Create an Okta Web app

Follow the steps on [the Okta documentation](https://developer.okta.com/docs/guides/sign-into-web-app/nodeexpress/main/#understand-the-callback-route) to create Okta web app and get client ID, client secret and issuer

### Create the strategy instance

```typescript
// app/utils/auth.server.ts
import { Authenticator } from "remix-auth";
import { OktaStrategy } from "remix-auth-okta";

// Create an instance of the authenticator, pass a generic with what your
// strategies will return and will be stored in the session
export const authenticator = new Authenticator<User>(sessionStorage);

let oktaStrategy = new OktaStrategy(
  {
    // example of issuer: https://dev-1234.okta.com/oauth2/default
    issuer: "YOUR_OKTA_ISSUER", 
    clientID: "YOUR_OKTA_CLIENT_ID",
    clientSecret: "YOUR_OKTA_CLIENT_SECRET",
    callbackURL: "https://your-app-domain.com/auth/okta/callback",
  },
  async ({ accessToken, refreshToken, extraParams, profile }) => {
    // Get the user data from your DB or API using the tokens and profile
    return User.findOrCreate({ email: profile.email });
  }
);

authenticator.use(oktaStrategy);
```

### Setup your routes

```typescript
// app/routes/login.tsx
export default function Login() {
  return (
    <Form action="/auth/okta" method="post">
      <button>Login with Okta</button>
    </Form>
  );
}
```


```typescript
// app/routes/auth/okta.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = () => redirect("/login");

export let action: ActionFunction = ({ request }) => {
  return authenticator.authenticate("okta", request);
};

```

```typescript
// app/routes/auth/okta/callback.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = ({ request }) => {
  return authenticator.authenticate("okta", request, {
    successRedirect: "/private",
    failureRedirect: "/login",
  });
};

```
