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

Validate a candidate password against the project's policy in one call:

```
let result = try await client.validatePassword("candidate")
if result.valid {
    // ok to submit
}
```

Or fetch the policy once and classify locally — useful for live-as-you-type validation:

```
let policy = try await client.passwordCompliancy()
let result = PreludeSessionClient.validate(password: "candidate", against: policy)
```

#### Session lifecycle

```
try await client.refresh()      // refreshes the access token
try await client.logout()       // revokes the session and clears local tokens

let profile = await client.profile      // currently signed-in user, if any
let token   = await client.accessToken  // the access token, if any
```

Protected requests auto-refresh expired access tokens transparently, so most apps will not need to call `refresh()` explicitly.

#### Step-up authentication

Some operations (e.g. changing the password) require a fresh proof of identity. Request the scope, deliver the OTP, then submit the code:

```
let challenge = try await client.requestStepUp(scope: "prld:pwd:write")
try await client.sendStepUpOTP(challenge)            // POST /otp
let next = try await client.submitStepUpOTP(challenge, code: "123456")

// `next == nil` means the flow completed and the session now
// carries the requested scope. A non-nil value is the next
// challenge in a multi-step flow — call `sendStepUpOTP` on it
// to deliver the next code.
```

`client.activeStepUp` exposes the most recent in-flight challenge so a UI can resume from a cold start.

#### Change password

After completing a step-up for `prld:pwd:write`:

```
try await client.changePassword(RedactedString("new-password"))
```

The SDK drops the granted scope locally on success so the same token cannot reset the password again.

#### Manage active sessions

List the user's sessions across devices and revoke them individually or in bulk:

```
let page = try await client.listSessions(ListSessionsOptions(limit: 20))

try await client.revokeSessions(.others)            // keep this device, sign out the rest
try await client.revokeSessions(.session(id: id))   // revoke a specific session
try await client.revokeSessions(.all)               // including this device
```

Revoking the current session (`.all`, `.mine`, or its specific id) also wipes the local credentials, mirroring `logout()`.

#### Migrate a legacy session

Exchange an existing bearer token from a previous authentication system for a Prelude session:

```
let user = try await client.migrate(MigrateOptions(token: "legacy-bearer"))
```

Idempotent: a valid cached session short-circuits the network call, so it is safe to call on every launch.

#### Endpoint configuration

```
let client = try PreludeSessionClient(
    endpoint: .default,                   // or .custom("https://staging.example")
    timeout: 10.0
)
```

Use `.default` in production. `.custom(...)` is intended for staging or local development.
