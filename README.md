# Readme
### Usage

The Apple Session SDK lets you sign users into your iOS app and manages the resulting session — tokens, refresh, logout — against the Prelude session API.

It is provided as a regular Swift package that you can [import as a dependency directly into your iOS application](https://developer.apple.com/documentation/xcode/adding-package-dependencies-to-your-app).

#### Email OTP login

Send a one-time code to the user's email address, then submit the code they entered. The SDK persists the resulting tokens in the Keychain.

```
import PreludeSession

let client = try PreludeSessionClient()

try await client.startOTPLogin(
    StartOTPLoginOptions(
        identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
    )
)

let user = try await client.checkOTP("123456")
```

If the user wants the code resent, call `client.resendOTP()`.

#### Email and password login

```
let user = try await client.loginWithPassword(
    LoginWithPasswordOptions(
        emailAddress: "alice@example.com",
        password: "correct horse battery staple"
    )
)
```

#### Password validation

Fetch the password policy configured on your project and validate a candidate password locally before submitting it:

```
let policy = try await client.passwordCompliancy()
let result = try await client.validatePassword("candidate", against: policy)
if result.valid {
    // ok to submit
}
```

#### Session lifecycle

```
try await client.refresh()      // refreshes the access token
try await client.logout()       // revokes the session and clears local tokens

let profile = await client.profile      // currently signed-in user, if any
let token   = await client.accessToken  // the access token, if any
```

Protected requests auto-refresh expired access tokens transparently, so most apps will not need to call `refresh()` explicitly.

#### Endpoint configuration

```
let client = try PreludeSessionClient(
    endpoint: .default,                   // or .custom("https://staging.example")
    timeout: 10.0
)
```

Use `.default` in production. `.custom(...)` is intended for staging or local development.
