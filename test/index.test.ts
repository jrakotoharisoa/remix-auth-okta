import { createCookieSessionStorage, json } from "@remix-run/server-runtime";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";
import { OAuth2StrategyVerifyParams } from "remix-auth-oauth2";
import {
  OktaExtraParams,
  OktaProfile,
  OktaStrategy,
  OktaStrategyOptions,
} from "../src";

enableFetchMocks();

describe(OktaStrategy, () => {
  const verify = jest.fn();
  const sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });

  beforeEach(() => {
    jest.resetAllMocks();
    fetchMock.resetMocks();
  });

  describe("Authorization Code flow", () => {
    const options: OktaStrategyOptions = Object.freeze({
      flow: "Code",
      issuer: "https://okta.issuer.come",
      clientID: "CLIENT_ID",
      clientSecret: "CLIENT_SECRET",
      callbackURL: "https://mysite.com/okta/callback",
    });

    test("should have the scope `openid profile email` as default", async () => {
      const request = new Request("https://mysite.com/okta/auth");
      const strategy = new OktaStrategy(options, verify);
      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
        });
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        const location = error.headers.get("Location");

        if (!location) throw new Error("No redirect header");

        const redirectUrl = new URL(location);

        expect(redirectUrl.searchParams.get("scope")).toBe(
          "openid profile email"
        );
      }
    });

    test("should allow changing the scope", async () => {
      const strategy = new OktaStrategy(
        { ...options, scope: "custom scope" },
        verify
      );
      const request = new Request("https://mysite.com/okta/auth");

      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
        });
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        const location = error.headers.get("Location");

        if (!location) throw new Error("No redirect header");

        const redirectUrl = new URL(location);

        expect(redirectUrl.searchParams.get("scope")).toBe("custom scope");
      }
    });

    test("should call verify with the access token, refresh token, extra params, user profile and context", async () => {
      const strategy = new OktaStrategy(options, verify);

      const session = await sessionStorage.getSession();
      session.set("oauth2:state", "random-state");

      const request = new Request(
        `${options.callbackURL}?state=random-state&code=random-code`,
        {
          headers: { cookie: await sessionStorage.commitSession(session) },
        }
      );

      fetchMock.once(
        JSON.stringify({
          access_token: "random-access-token",
          refresh_token: "random-refresh-token",
          id_token: "random.id.token",
        })
      );

      fetchMock.once(
        JSON.stringify({
          sub: "id",
          name: "Name",
          preferred_username: "Preferred username",
          nickname: "Nickname",
          given_name: "Given name",
          middle_name: "Middle name",
          family_name: "Family name",
          profile: "Profile",
          zoneinfo: "fr",
          locale: "fr",
          updated_at: "date",
          email: "example@email.com",
          email_verified: true,
        })
      );

      const context = { test: "it works" };

      await strategy.authenticate(request, sessionStorage, {
        sessionKey: "user",
        context,
      });

      const [url, mockRequest] = fetchMock.mock.calls[0];
      const body = mockRequest?.body as URLSearchParams;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const headers = mockRequest?.headers as any;

      expect(url).toBe(`${options.issuer}/v1/token`);

      expect(mockRequest?.method as string).toBe("POST");
      expect(headers["Content-Type"]).toBe("application/x-www-form-urlencoded");

      expect(body.get("client_id")).toBe(options.clientID);
      expect(body.get("client_secret")).toBe(options.clientSecret);
      expect(body.get("grant_type")).toBe("authorization_code");
      expect(body.get("code")).toBe("random-code");

      expect(verify).toHaveBeenLastCalledWith({
        accessToken: "random-access-token",
        refreshToken: "random-refresh-token",
        extraParams: { id_token: "random.id.token" },
        profile: {
          provider: "okta",
          id: "id",
          displayName: "Name",
          name: {
            familyName: "Family name",
            givenName: "Given name",
            middleName: "Middle name",
          },
          email: "example@email.com",
        },
        context,
      } as OAuth2StrategyVerifyParams<OktaProfile, OktaExtraParams>);
    });
  });

  describe("Password flow", () => {
    const options: OktaStrategyOptions = Object.freeze({
      flow: "Password",
      issuer: "https://okta.issuer.com",
      oktaDomain: "https://okta.domain.com",
      clientID: "CLIENT_ID",
      clientSecret: "CLIENT_SECRET",
      callbackURL: "https://mysite.com/okta/callback",
    });

    test("if user is already in the session redirect to `/`", async () => {
      const strategy = new OktaStrategy(options, verify);

      const session = await sessionStorage.getSession();
      session.set("user", { id: "123" });

      const request = new Request("https://example.com/login", {
        headers: { cookie: await sessionStorage.commitSession(session) },
      });

      const user = await strategy.authenticate(request, sessionStorage, {
        sessionKey: "user",
      });

      expect(user).toEqual({ id: "123" });
    });

    test("if user is already in the session and successRedirect is set throw a redirect", async () => {
      const strategy = new OktaStrategy(options, verify);

      const session = await sessionStorage.getSession();
      session.set("user", { id: "123" });

      const request = new Request("https://example.com/login", {
        headers: { cookie: await sessionStorage.commitSession(session) },
      });

      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
          successRedirect: "/dashboard",
        });
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        expect(error.headers.get("Location")).toBe("/dashboard");
      }
    });

    test("should throw if no email in form request", async () => {
      const strategy = new OktaStrategy(options, verify);
      const body = new FormData();
      body.set("password", "test@example.com");
      const request = new Request("", { body, method: "POST" });
      const response = json(
        { message: "Bad request, missing email and password." },
        { status: 400 }
      );

      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
        });
        fail("test fail");
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        expect(error).toEqual(response);
      }
    });

    test("should throw if no password in form request", async () => {
      const strategy = new OktaStrategy(options, verify);
      const body = new FormData();
      body.set("email", "test@example.com");
      const request = new Request("", { body, method: "POST" });
      const response = json(
        { message: "Bad request, missing email and password." },
        { status: 400 }
      );

      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
        });
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        expect(error).toEqual(response);
      }
    });

    test("should redirect to authorization if request is not the callback", async () => {
      let strategy = new OktaStrategy(options, verify);

      const body = new FormData();
      body.set("email", "test@example.com");
      body.set("password", "password");
      const request = new Request("http://example.com/login", {
        body,
        method: "POST",
      });
      fetchMock.once(
        JSON.stringify({
          sessionToken: "session-token",
        })
      );
      try {
        await strategy.authenticate(request, sessionStorage, {
          sessionKey: "user",
        });
      } catch (error) {
        if (!(error instanceof Response)) throw error;

        let redirect = new URL(error.headers.get("Location") as string);

        let session = await sessionStorage.getSession(
          error.headers.get("Set-Cookie")
        );

        expect(fetchMock.mock.calls[0][0]).toBe(
          `${options.oktaDomain}/api/v1/authn`
        );
        const body = JSON.parse(
          (fetchMock.mock.calls[0][1]?.body as string) || ""
        );
        expect(body.username).toBe("test@example.com");
        expect(body.password).toBe("password");
        expect(error.status).toBe(302);

        expect(redirect.pathname).toBe("/v1/authorize");
        expect(redirect.searchParams.get("response_type")).toBe("code");
        expect(redirect.searchParams.get("client_id")).toBe(options.clientID);
        expect(redirect.searchParams.get("sessionToken")).toBe("session-token");
        expect(redirect.searchParams.get("redirect_uri")).toBe(
          options.callbackURL
        );
        expect(redirect.searchParams.has("state")).toBeTruthy();

        expect(session.get("oauth2:state")).toBe(
          redirect.searchParams.get("state")
        );
      }
    });
  });
});
