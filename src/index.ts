import { json, SessionStorage } from "@remix-run/server-runtime";
import { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import {
  OAuth2Strategy,
  OAuth2StrategyOptions,
  OAuth2StrategyVerifyParams,
} from "remix-auth-oauth2";

export interface OktaProfile {
  provider: string;
  id: string;
  displayName: string;
  name: {
    familyName: string;
    givenName: string;
    middleName: string;
  };
  email: string;
}

type OktaUserInfo = {
  sub: string;
  name: string;
  preferred_username: string;
  nickname: string;
  given_name: string;
  middle_name: string;
  family_name: string;
  profile: string;
  zoneinfo: string;
  locale: string;
  updated_at: string;
  email: string;
  email_verified: boolean;
};

export type OktaStrategyOptions = Omit<
  OAuth2StrategyOptions,
  "authorizationURL" | "tokenURL"
> & {
  scope?: string;
  issuer: string;
  flow: "Password" | "Code";
} & (
    | {
        flow: "Password";
        oktaDomain: string;
      }
    | { flow: "Code"; oktaDomain?: never }
  );

export type OktaExtraParams = Record<string, string | number>;

export class OktaStrategy<User> extends OAuth2Strategy<
  User,
  OktaProfile,
  OktaExtraParams
> {
  name = "okta";
  private userInfoURL: string;
  private authenticationURL: string;
  private readonly scope: string;
  private readonly flow: "Code" | "Password";
  private sessionToken = "";
  constructor(
    {
      issuer,
      scope = "openid profile email",
      clientID,
      clientSecret,
      callbackURL,
      ...rest
    }: OktaStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<OktaProfile, OktaExtraParams>
    >
  ) {
    super(
      {
        authorizationURL: `${issuer}/v1/authorize`,
        tokenURL: `${issuer}/v1/token`,
        clientID,
        clientSecret,
        callbackURL,
      },
      verify
    );
    this.scope = scope;
    this.userInfoURL = `${issuer}/v1/userinfo`;
    this.authenticationURL = `${issuer}/api/v1/authn`;
    this.flow = rest.flow ?? "Code";
    this.authenticationURL =
      rest.flow === "Code" ? "" : `${rest.oktaDomain}/api/v1/authn`;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    if (this.flow === "Code") {
      return super.authenticate(request, sessionStorage, options);
    }

    let session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );

    let user: User | null = session.get(options.sessionKey) ?? null;
    if (user) {
      return this.success(user, request.clone(), sessionStorage, options);
    }

    const form = await request.formData();
    const email = form.get("email");
    const password = form.get("password");
    if (!email || !password) {
      throw json(
        { message: "Bad request, missing email and password." },
        { status: 400 }
      );
    }
    this.sessionToken = await this.getSessionTokenWith(
      email.toString(),
      password.toString()
    );

    return super.authenticate(request, sessionStorage, options);
  }

  private async getSessionTokenWith(
    email: string,
    password: string
  ): Promise<string> {
    let response = await fetch(this.authenticationURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: email,
        password,
      }),
    });

    if (!response.ok) {
      try {
        let body = await response.text();

        throw new Error(body);
      } catch (error) {
        throw error;
      }
    }
    const data = await response.json();
    return data.sessionToken;
  }

  protected authorizationParams() {
    return new URLSearchParams({
      scope: this.scope,
      sessionToken: this.sessionToken,
    });
  }

  protected async userProfile(accessToken: string): Promise<OktaProfile> {
    const response = await fetch(this.userInfoURL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const profile: OktaUserInfo = await response.json();
    return {
      provider: "okta",
      id: profile.sub,
      name: {
        familyName: profile.family_name,
        givenName: profile.given_name,
        middleName: profile.middle_name,
      },
      displayName: profile.name ?? profile.preferred_username,
      email: profile.email,
    };
  }
}
