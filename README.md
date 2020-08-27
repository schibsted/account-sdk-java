# account-sdk-java
Java SDK for Schibsted account

## Downloading
Get the SDK via Gradle:
```
compile 'com.schibsted.account:account-sdk-java:<version>'
```

## Usage

JavaDocs are available [here](https://pages.github.com/schibsted/account-sdk-java/).

### Quickstart guide

All operations are performed via the `AuthClient`. Instantiate it via the object builder:
```java
import com.schibsted.account.AuthClient;
import com.schibsted.account.ClientCredentials;

AuthClient client = new AuthClient.Builder(
    new ClientCredentials(<client id>, <client secret>),
    AuthClient.Environment.PRE)
   .build();
```

#### Request a client token
Using your client credentials you can obtain a client token with the necessary scopes:

```java
import com.schibsted.account.token.AccessToken;

AccessToken accessToken = client.clientCredentialsGrant(<scopes>);
```

#### Request user tokens
When you have an OAuth authorization code you can obtain user tokens:

```java
import com.schibsted.account.token.UserTokens;

UserTokens userTokens = client.authorizationCodeGrant(<auth code>, <redirect uri>, <expected nonce>);
```

If the access token has expired, you can obtain a new one by using the refresh token:
```java
UserTokens refreshed = client.refreshTokenGrant(userTokens.getRefreshToken().getToken());
```

#### Introspect tokens
When you receive a token it can be introspected to get the associated authorization data. There are two methods
of introspection:
* "remote introspection": by making an [introspection request](https://tools.ietf.org/html/rfc7662#section-2.1) the
  authorization data is returned from Schibsted account.
* "local introspection": by verifying the signature and the tokens validity, the authorization data can be read directly
  from the claims of the token. **Note:** Some user tokens - those signed with a symmetric secret key - can not be
  introspected locally. Only remote introspection is supported for those tokens.
