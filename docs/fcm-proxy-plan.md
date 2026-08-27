# FCM branch — design only, not implemented

**Status: deferred.** This document is preparation and design, requested
explicitly as documentation-only work. No FCM code exists in this repo, no
new environment variables are defined, nothing here is deployed. It exists
so the eventual implementation has a starting point and doesn't repeat this
research. Companion entry: `docs/TODO.md` in the `nks-nextcloud-talk` repo
(commit `75e1342`).

## Why

Android's push path today doesn't go through this proxy at all. The client
uses `org.unifiedpush.android:embedded-fcm-distributor`, which registers a
subscription endpoint at `https://fcm.distributor.unifiedpush.org/wpfcm` —
a public gateway run by the UnifiedPush project that accepts a Web Push
request and re-delivers it as an FCM message through Google Play Services.
No Firebase SDK, no `google-services.json` — the library talks to Play
Services over the older C2DM broadcast mechanism. Content is encrypted
(`aes128gcm`, keyed by the subscription), so neither the UnifiedPush gateway
nor Google can read it — but both see metadata (which app, how often,
approximate size, timing).

The goal is to route Android through `push.example.com`, the same
proxy iOS uses, instead of the UnifiedPush gateway, for the same reason iOS
needed its own proxy: don't depend on infrastructure this project doesn't
control for something as basic as message delivery.

**The Nextcloud server side does not change at all.** `Push.php` has no
platform-specific logic — it groups queued notifications by the
`proxyserver` column and posts each group to whatever URL is stored there.
Whether that URL's owner talks to APNs or FCM behind the scenes is entirely
this proxy's decision, invisible to Nextcloud.

## FCM v1 send branch (design)

Google's current API is HTTP v1, not the deprecated legacy HTTP/XMPP API.
Shape, alongside the existing APNs branch:

- **Auth**: a Google Cloud **service account** (JSON key), not a static
  server key. Mint a short-lived OAuth2 access token from it (JWT
  bearer-token grant against `https://oauth2.googleapis.com/token`, scope
  `https://www.googleapis.com/auth/firebase.messaging`) and cache it like
  `apns.ApnsAuthTokenFactory` already caches the APNs JWT — same shape,
  different signing key and token endpoint. Google client libraries
  (`google-auth`) handle this; hand-rolling it is also small (RS256 JWT,
  similar complexity to the existing ES256 APNs one) if avoiding the extra
  dependency matters more than reusing a maintained library.
- **Endpoint**: `POST https://fcm.googleapis.com/v1/projects/<project-id>/messages:send`,
  one request per device (v1 has no native multicast; batch via HTTP/1.1
  keep-alive or concurrent requests, not a single call).
- **Payload**: `data`-only, no `notification` block — exactly like the
  APNs branch already does with `mutable-content` + `nc-subject`, so the
  app keeps unpacking encrypted content itself instead of trusting a
  plaintext OS-rendered banner:
  ```json
  {
    "message": {
      "token": "<fcm registration token>",
      "data": { "nc-subject": "<base64 ciphertext, same field as today>" },
      "android": { "priority": "high" }
    }
  }
  ```
- **Priority mapping**: same source as APNs — `Push::getNotifTopicAndUrgency()`
  gives `high`/`normal`; FCM's `android.priority` takes exactly those two
  values, no translation table needed.
- **Dead-token handling**: FCM v1 returns `404 NOT_FOUND` or
  `400 INVALID_ARGUMENT` (reason `UNREGISTERED`) for a token that's gone —
  the direct FCM analog of APNs' `410`/`BadDeviceToken`. Same response
  contract this proxy already implements: delete the row, report the
  `deviceIdentifier` as `unknown` so Nextcloud cleans up its copy too.

## Telling APNs and FCM tokens apart

The proxy needs to route to the right provider without the client
explicitly declaring one. Cheapest reliable signal: **shape of the push
token itself**.

- APNs device tokens: 64 lowercase hex characters, `^[0-9a-f]{64}$` — this
  is already the exact validation `app/server.py` applies today (S2).
- FCM registration tokens: no fixed length or fixed charset Google
  guarantees long-term, but never matches the APNs pattern — different
  alphabet (mixed case, `:`, `-`, `_`), always well over 64 characters in
  practice.

Consequence for existing code: today's `_PUSH_TOKEN_RE` in
`app/server.py` rejects anything that isn't a 64-char lowercase hex string.
Adding FCM support means that check can no longer be the *only* gate — it
has to become "matches APNs shape (→ APNs branch) **or** matches FCM shape
(→ FCM branch), reject anything that matches neither." The registration
row also needs a stored provider flag (or the format is re-derived from the
token on every send, cheaper but repeats the check) so `POST /notifications`
knows which HTTP client and payload shape to use per device without
re-guessing from partial data. Not implemented here — just the shape of the
change the eventual patch has to make, so S2 doesn't get loosened
carelessly when it happens.

## Open question — not decided here

Two ways to get Android talking to this proxy, with real tradeoffs either
way. Deliberately not choosing one:

**Option A — keep the Android client on its current Web Push contract
(`api/v2/webpush`).** The client's registration code doesn't change at all.
This proxy would need to implement a *second* endpoint surface speaking
Nextcloud's native Web Push protocol (RFC 8291/8292 message encryption,
VAPID) instead of push-v2's `/devices` + `/notifications`. More work in
this proxy (a second protocol, real Web Push decryption before an FCM
send), zero work in the Android app.

**Option B — move Android onto push-v2 `/devices`, same contract as iOS.**
One registration/notification contract for both platforms in this proxy
(what this repo already implements, extended with a provider branch on
send). Less proxy-side protocol surface, but requires changing the Android
client's registration flow to call `POST /devices` with a device public
key, `deviceIdentifier`, `deviceIdentifierSignature` — the same fields iOS
already sends — and dropping the `embedded-fcm-distributor` dependency.
Real client-side work, in the Android app's own repo, not this one.

Whoever picks this up needs input from whoever owns the Android client
work at the time — this doc intentionally stops short of a recommendation.

## What's needed on Google's side

- A **Firebase/Google Cloud project** dedicated to this app (or reused if
  one already exists for the project) — FCM v1 is unavailable without a
  project ID to send through.
- A **Sender ID** for that project, which the Android app has to be built
  against so the FCM tokens it generates on-device are addressable through
  our project. This is what actually changes on Android's build: today's
  `embedded-fcm-distributor` doesn't need any of this, since it isn't
  talking to a Firebase project of ours — it rides UnifiedPush's own. Once
  Android registers directly for FCM under our project, the app needs at
  minimum the project's Sender ID at build time; going through the
  Firebase SDK proper (rather than the bare FCM registration API) would
  also mean bundling `google-services.json`, a heavier dependency this repo
  has no opinion on — that call belongs with whoever picks up the Android
  side.
- A **service account** with the Firebase Cloud Messaging API enabled,
  key exported as JSON — this proxy's analog of the `.p8` APNs key: never
  committed, mounted read-only, referenced by path via an env var (not
  defined yet, since nothing is implemented).

## Non-goals of this document

No code in this repo changes because of it. No new environment variables
exist yet — `NEXTCLOUD_SUBSCRIPTION_KEY`, `APNS_*`, etc. remain the
complete list until an actual FCM implementation lands. Nothing here is
deployed, and this proxy keeps doing exactly what it does today: APNs only.
