# Session Monitor

Standalone invitation-only multi-user page-load monitoring app. It runs a background check per account: 57 public page visits per cycle, two minutes apart, repeating until stopped. It only loads pages, never clicks controls or submits forms.

Use only sites you own or have permission to monitor. Local/private addresses and unsupported URL schemes are blocked.

## Deploy

1. Create a Render Blueprint from the `phenestypheness-debug/session-monitor` repository.
2. Review Render's paid Starter service and persistent disk pricing.
3. Set a long private `SIGNUP_INVITE_CODE`; Render generates `SECRET_KEY`.
4. Deploy and open the Render URL.
5. Sign up using the invite code, then add an authorized URL and start its check.

The service is standalone and separate from the previous `2543ty/Automation` project. See the repository files for details.
