import { createCookieSessionStorage } from "@remix-run/server-runtime";
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
  let verify = jest.fn();
  // You will probably need a sessionStorage to test the strategy.
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });

  let options: OktaStrategyOptions = Object.freeze({
    flow: "Code",
    issuer: "https://okta.issuer.come",
    clientID: "CLIENT_ID",
    clientSecret: "CLIENT_SECRET",
    callbackURL: "https://mysite.com/okta/callback",
  });
  beforeEach(() => {
    jest.resetAllMocks();
    fetchMock.resetMocks();
  });

  test("should have the name of the strategy", () => {
    let strategy = new OktaStrategy(options, verify);
    expect(strategy.name).toBe("okta");
  });

  test("should have the scope `openid profile email` as default", async () => {
    let strategy = new OktaStrategy(options, verify);

    let request = new Request("https://mysite.com/okta/auth");

    try {
      await strategy.authenticate(request, sessionStorage, {
        sessionKey: "user",
      });
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      let location = error.headers.get("Location");

      if (!location) throw new Error("No redirect header");

      let redirectUrl = new URL(location);

      expect(redirectUrl.searchParams.get("scope")).toBe(
        "openid profile email"
      );
    }
  });

  test("should allow changing the scope", async () => {
    let strategy = new OktaStrategy(
      { ...options, scope: "custom scope" },
      verify
    );
    let request = new Request("https://mysite.com/okta/auth");

    try {
      await strategy.authenticate(request, sessionStorage, {
        sessionKey: "user",
      });
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      let location = error.headers.get("Location");

      if (!location) throw new Error("No redirect header");

      let redirectUrl = new URL(location);

      expect(redirectUrl.searchParams.get("scope")).toBe("custom scope");
    }
  });

  test("should call verify with the access token, refresh token, extra params, user profile and context", async () => {
    let strategy = new OktaStrategy(options, verify);

    let session = await sessionStorage.getSession();
    session.set("oauth2:state", "random-state");

    let request = new Request(
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

    let context = { test: "it works" };

    await strategy.authenticate(request, sessionStorage, {
      sessionKey: "user",
      context,
    });

    let [url, mockRequest] = fetchMock.mock.calls[0];
    let body = mockRequest?.body as URLSearchParams;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let headers = mockRequest?.headers as any;

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
