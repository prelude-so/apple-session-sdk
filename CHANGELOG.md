# Changelog

Notable changes to `PreludeSession` (the Prelude Apple Session SDK).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-05-09

### Added
- `listSessions(_:)` and `revokeSessions(_:)` for managing the user's active sessions, with `RevokeTarget.all`, `.others`, `.mine`, and `.session(id:)`.
- `sendStepUpOTP(_:)` — caller-driven OTP delivery for step-up flows.
- `migrate(_:)` — exchange a legacy bearer token for a Prelude session via PKCE-bound `/migration` ⇒ `/login/finalize`.
- `activeStepUp` accessor on `PreludeSessionClient` so callers can observe an in-flight challenge without holding it themselves.
- `PreludeSessionClient.validate(password:against:)` static helper for pure local password classification (no network call).
- `requestStepUp(scope:metadata:)` accepts an optional `[String: String]` metadata bag forwarded to the server's step-up audit hook.
- New typed errors: `expiredChallengeToken`, `tokenReused`, `notFound`, `conflict`.
- Request bodies carrying secrets (password, OTP code, migration token, step-up code) now redact plaintext from `description` / `debugDescription` / `Mirror`.
- Expanded test coverage across login, refresh, logout, step-up, sessions, migration, error mapping, and DPoP flows.

### Changed
- **Behavior change:** `requestStepUp(scope:)` and `submitStepUpOTP(_:code:)` no longer auto-fire `POST /otp`. Callers must invoke `sendStepUpOTP(_:)` explicitly.
- `logout()` now wipes domain-scoped HTTP cookies alongside Keychain credentials.
- `logout()` signs `/revoke` from a pre-wipe credential snapshot; signing failures degrade gracefully so the local logout always lands.
- `revokeSessions` and `logout` bump the session epoch after the local wipe so a racing refresh cannot resurrect stores that were just emptied.
- `changePassword` clears the active step-up handle on every outcome.

### Fixed
- DPoP `htu` now canonicalizes scheme and host to lowercase (RFC 3986), preventing proof mismatch on mixed-case base URLs.
- `refreshAfterStepUp` invalidates the access-token cache before draining any in-flight refresh, eliminating a narrow window where a concurrent `refresh()` could double-spend the refresh token.
- `revokeSessions` rejects empty / whitespace-only session ids with a typed configuration error instead of relying on a server 400.
- Server 5xx errors now surface as `PreludeSessionError.internalServerError` (the backend emits code `internal`; the SDK previously expected `internal_server_error` and fell through to `.generic`).
- Decoded session payloads are now immutable.

## [0.1.0] - 2026-04-29

Initial release.

### Added
- Email OTP login: `startOTPLogin`, `resendOTP`, `checkOTP`.
- Email and password login: `loginWithPassword`.
- Password validation against the project policy: `passwordCompliancy()` and `validatePassword(_:)`.
- Session lifecycle: `refresh()`, `logout()`.
- Session inspection: `profile`, `accessToken`.
- Automatic access-token refresh on protected requests.
- Optional `PreludeSignalsAdapter` integration to attach a Prelude `dispatch_id` to login calls.

### Requirements
- iOS 15+
- Swift 5.7+ tools, Swift 5.10+ compiler
