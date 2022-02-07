import { SessionStorage } from "@remix-run/server-runtime";
import { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import {
  OAuth2Profile,
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
  "authorizationURL" | "tokenURL" | "callbackURL"
> & {
  scope?: string;
  issuer: string;
} & (
    | { flow: "Password"; callbackURL: never }
    | { flow?: "Code"; callbackURL: string }
  );

export type OktaExtraParams = Record<string, string | number>;

export class OktaStrategy<User> extends OAuth2Strategy<
  User,
  OktaProfile,
  OktaExtraParams
> {
  name = "okta";
  private userInfoURL: string;
  private readonly scope: string;
  private readonly flow: "Code" | "Password";
  constructor(
    {
      issuer,
      scope = "openid profile email",
      clientID,
      clientSecret,
      ...rest
    }: OktaStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<OAuth2Profile, OktaExtraParams>
    >
  ) {
    super(
      {
        authorizationURL: `${issuer}/v1/authorize`,
        tokenURL: `${issuer}/v1/token`,
        clientID,
        clientSecret,
        callbackURL: rest.flow === "Password" ? "" : rest.callbackURL,
      },
      verify
    );
    this.scope = scope;
    this.userInfoURL = `${issuer}/v1/userinfo`;
    this.flow = rest.flow ?? "Code";
  }

  authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    if (this.flow === "Code") {
      return super.authenticate(request, sessionStorage, options);
    }

    throw new Error("not implemented");
  }

  protected authorizationParams() {
    return new URLSearchParams({
      scope: this.scope,
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
