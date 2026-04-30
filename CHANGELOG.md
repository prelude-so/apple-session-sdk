# Changelog

Notable changes to `PreludeSession` (the Prelude Apple Session SDK).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-04-29

Initial release.

### Added
- Email OTP login: `startOTPLogin`, `resendOTP`, `checkOTP`.
- Email and password login: `loginWithPassword`.
- Password validation against the project policy: `passwordCompliancy()` and `validatePassword(_:against:)`.
- Session lifecycle: `refresh()`, `logout()`.
- Session inspection: `profile`, `accessToken`.
- Automatic access-token refresh on protected requests.
- Optional `PreludeSignalsAdapter` integration to attach a Prelude `dispatch_id` to login calls.

### Requirements
- iOS 15+
- Swift 5.7+ tools, Swift 5.10+ compiler
