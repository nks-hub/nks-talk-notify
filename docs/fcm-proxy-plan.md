# FCM branch — implemented

**Status: implemented, code-complete, verified with local tests. Not yet
live in production** — the real Firebase project, Sender ID, and service
account JSON are still being provisioned (Firebase Console, account "the operator account"); this proxy's FCM branch is inert until `FCM_PROJECT_ID` and
`FCM_SERVICE_ACCOUNT_PATH` are set on the deployment, which happens once
those credentials exist. Superseded design doc — the original "documentation
only, no implementation" scope changed after the owner decided Android's
native push path *is* this proxy, not a Web Push contract this proxy would
need to speak. Companion entry: `docs/TODO.md` in the `nks-nextcloud-talk`
repo (commit `75e1342`, itself superseded by that repo's own notifications
architecture doc).

## Why

Android's push path used to route entirely outside this proxy. The client
used `org.unifiedpush.android:embedded-fcm-distributor`, which registers a
subscription endpoint at `https://fcm.distributor.unifiedpush.org/wpfcm` —
a public gateway run by the UnifiedPush project that accepts a Web Push
request and re-delivers it as an FCM message through Google Play Services.
Content stayed encrypted (`aes128gcm`, keyed by the subscription), but
metadata (which app, how often, approximate size, timing) was visible to
that gateway and to Google.

Android's native push path is now this proxy — the same push-v2 contract
iOS already uses, not a second protocol. UnifiedPush Web Push remains in
the app as a switchable fallback (Settings → Push notifications, no
rebuild needed to switch), not the default.

**The Nextcloud server side does not change at all.** `Push.php` has no
platform-specific logic — it groups queued notifications by the
`proxyserver` column and posts each group to whatever URL is stored there.
Whether that URL's owner talks to APNs or FCM behind the scenes is entirely
this proxy's decision, invisible to Nextcloud. Verified true after the FCM
branch landed: still zero Nextcloud-server changes.

## What's in this repo

- `app/fcm.py` — `FcmAuthTokenFactory` (RS256 JWT service-account bearer
  grant, cached the same way `apns.ApnsAuthTokenFactory` caches its ES256
  JWT) and `FcmClient` (`POST /v1/projects/<id>/messages:send`, `data`-only
  payload, `android.priority` mapping, FCM v1 `errorCode` parsing).
- `app/server.py::token_kind()` — the APNs/FCM shape-based dispatch
  described below, used by both registration (`register_device`) and
  delivery (`send_notifications` → `_send_via_apns()` / `_send_via_fcm()`).
- `app/config.py` — `APNS_*` and `FCM_*` are each independently optional;
  `Config.__post_init__` requires at least one complete set, whichever
  branch is missing just logs a warning and that provider's tokens fail
  cleanly instead of crashing anything.
- `.env.example` / `docker-compose.yml` — `FCM_PROJECT_ID`,
  `FCM_SERVICE_ACCOUNT_PATH` (+ `_HOST_PATH` for compose, `/dev/null`
  fallback so the mount stays valid with FCM unconfigured).
- Tests: `tests/test_fcm.py` (JWT claims, signature, payload shape, error
  parsing) and the FCM sections of `tests/test_server.py` (token
  detection, dispatch, the `UNREGISTERED`-vs-`INVALID_ARGUMENT` mapping, a
  missing-FCM-client degrades to `failed`). RED-verified the same way as
  the S1–S8 security fixes: token detection and the `unknown` mapping were
  each temporarily broken and confirmed to fail their tests before being
  restored.

See `README.md` for the actual wire contract, security model, and
deployment instructions — this document stays about the FCM branch
specifically, not a duplicate of the whole README.

## Telling APNs and FCM tokens apart

No client declares a provider explicitly at registration — the proxy
infers it from token shape (`app/server.py::token_kind()`):

- APNs: `^[0-9a-f]{64}$` — unchanged from before FCM existed.
- FCM: `^[A-Za-z0-9_:-]{32,4096}$` — a strict whitelist, not "anything
  that isn't APNs". This matters because the token is attacker-influenced
  data handed onward to an external API (today: into APNs' URL path,
  `f"/3/device/{device_token}"`; FCM's token travels in the JSON body
  instead, but gets the same strict treatment on principle, not because
  the URL-path risk applies identically). A token matching neither shape
  is rejected outright, `400 INVALID_PUSH_TOKEN`.

Nothing is stored to remember which provider a device uses — `token_kind()`
re-derives it from the stored `push_token` at send time too. Cheap pure
function, no schema/migration needed to add this.

## What was needed on Google's side

- A Firebase/Google Cloud project (`FCM_PROJECT_ID`) — being created under
  the "the operator account" account.
- A service account with the Firebase Cloud Messaging API enabled, key
  exported as JSON (`FCM_SERVICE_ACCOUNT_PATH`) — this proxy's exact analog
  of the `.p8` APNs key: never committed, mounted read-only.
- On the Android build side (outside this repo): a Sender ID from that
  project, since `embedded-fcm-distributor` rides UnifiedPush's own
  Firebase project today and needs to register against NKS's own project
  instead once it talks to this proxy directly.

## What's still open

- Real Firebase project/service account credentials — pending, tracked by
  the owner in the Firebase Console. Once they exist: set `FCM_PROJECT_ID`
  and `FCM_SERVICE_ACCOUNT_PATH` (`_HOST_PATH` for compose) on the
  deployment and restart; no code or schema changes needed.
- Live end-to-end verification against a real FCM project and a real
  Android device/token — can't be done without those credentials. Local
  tests cover JWT construction, payload shape, and error-code mapping
  against synthetic responses; they don't prove Google's API accepts what
  this proxy sends until tested against the real endpoint.
- The Android client's own registration flow (calling `POST /devices` with
  its device public key, `deviceIdentifier`, `deviceIdentifierSignature`) —
  application-side work in the Android app's repo, not this one.
