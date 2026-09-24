# nks-talk-notify

A small self-hosted push gateway for Nextcloud's push-v2 protocol. It
receives signed, encrypted notifications from a Nextcloud server and hands
them to Apple Push Notification service (APNs, including PushKit for calls)
and Firebase Cloud Messaging (FCM HTTP v1).

It was written for [OwnTalk](https://github.com/nks-hub/nks-nextcloud-talk),
a third-party Nextcloud Talk client for Android, iOS and desktop. Nothing in
the protocol handling is specific to that app: any client that speaks
push-v2 and whose APNs key or Firebase project you control can use it.

The gateway is one Python process with a SQLite file. It has no admin UI,
no queue and no clustering.

## Why it exists

Nextcloud does not talk to APNs or FCM itself. The notifications app encrypts
each notification for the receiving device, signs it with the user's
identity key and posts it to a "push proxy" URL that the client chose when it
registered (`lib/Push.php`, `sendNotificationsToProxies()` in the
[notifications app](https://github.com/nextcloud/notifications)). The proxy
is what holds the provider credentials.

Nextcloud GmbH runs the default proxy, `https://push-notifications.nextcloud.com`.
It sends with Nextcloud GmbH's own APNs key and Firebase project, so it can
only reach their official apps. Apple and Google deliver a push only when
the sender's credentials belong to the receiving app. A third-party app with
its own bundle id and its own Firebase project therefore needs its own proxy,
and this is one.

While the app is open, Nextcloud's Client Push (`notify_push`) websocket can
deliver messages without any proxy. That stops as soon as the operating
system suspends the app, which on iOS happens within seconds. Only APNs or
FCM can wake a closed app.

## How a notification travels

```
 phone app                    Nextcloud server                 nks-talk-notify           Apple / Google
 ---------                    ----------------                 ---------------           --------------
 1. POST /ocs/.../api/v2/push  ──►  stores pushTokenHash,
    (pushTokenHash,                 devicePublicKey, proxyServer;
     devicePublicKey,               returns deviceIdentifier,
     proxyServer)                   signature, user publicKey
 2. POST /devices  ─────────────────────────────────────────►  verifies signature,
    (real push token,                                            stores token + key
     deviceIdentifier, signature,
     userPublicKey)
                              3. new notification:
                                 encrypt subject with the
                                 device key, sign with the
                                 user key, POST /notifications ─►  verifies signature
                                                                   against the stored key ──►  APNs / FCM
                                                                                                  │
 4. app extension decrypts the subject with the device private key  ◄────────────────────────────┘
```

Step 1 is Nextcloud's own API. The client sends `proxyServer`, the public
HTTPS URL of this gateway, and `pushTokenHash`, which is SHA-512 of the push
token. Nextcloud never sees the real token, so step 2 is where the client
gives the token to the gateway directly. The gateway computes
`sha512(pushToken)` over the UTF-8 token string the same way; if the client
hashes differently, deliveries will never match a device.

In step 3 Nextcloud groups queued notifications by `proxyserver` and posts
each group as `application/x-www-form-urlencoded`
`notifications[0]=<json>&notifications[1]=<json>…`. Each JSON entry carries
`deviceIdentifier`, `pushTokenHash`, `subject` (RSA ciphertext encrypted
with the device's public key), `signature` (RSA-SHA512 over the ciphertext,
made with the user's identity key), `priority` and `type`.

The gateway looks up the device, checks the token hash, verifies the
signature against the public key stored at registration, and sends:

- to APNs, an `alert` push with a generic title ("Nextcloud Talk"),
  `mutable-content: 1` and the ciphertext in `nc-subject`. The app's
  Notification Service Extension decrypts it and replaces the text before
  the banner appears. If the extension fails, the user sees the generic
  title.
- to APNs PushKit (`<topic>.voip`), when Nextcloud marks the entry
  `type=voip` and the device registered a separate VoIP token. Without a
  VoIP token the call arrives as an ordinary alert.
- to APNs as a silent `content-available` push for `type=background`
  (Nextcloud uses this to withdraw a notification).
- to FCM, a data-only message (`{"nc-subject": …}`) with
  `android.priority` taken from Nextcloud's `priority`. There is no
  `notification` block, so Android never shows the ciphertext itself; the
  app decrypts and displays it.

It answers Nextcloud with `{"unknown": [...], "failed": N}`. Nextcloud
deletes its own registration for every `deviceIdentifier` listed under
`unknown`, so the gateway only lists a device there when it has never seen
it or when APNs (`410 Unregistered`, `400 BadDeviceToken`) or FCM
(`UNREGISTERED`) says the token is permanently gone. Every other problem
counts as `failed`.

## What the gateway sees and stores

It cannot read notification content. The `subject` is encrypted with a key
that exists only on the device.

Per registered device it stores, in SQLite: `deviceIdentifier` (a SHA-512
digest Nextcloud derives from the user's cloud id and session token id; the
gateway never sees the inputs), the user's identity-proof public key, the
push token and its hash, the provider (`apns` or `fcm`), the APNs
environment, an optional PushKit token, and created/updated timestamps. It
does not store user names, server URLs, IP addresses or message metadata.

It does see, in transit, which device gets a notification and when, the
source IP of the Nextcloud server and of registering phones, and the
ciphertext size. Apple and Google see the same timing and target metadata
for anything delivered through them.

Access logs contain the peer address and request line. The query string is
never logged, and provider HTTP client logging is suppressed below WARNING
because the APNs URL contains the device token. The database file is created
with mode `0600`; treat it and its backups as sensitive, since the push
tokens are in clear text.

## Requirements

- Python 3.12 (the Docker image uses `python:3.12-slim`); dependencies are
  `httpx[http2]` and `cryptography` (`requirements.txt`).
- A public HTTPS hostname in front of the gateway. Nextcloud refuses a
  `proxyServer` that is not `https://`, except `http://localhost` and hosts
  ending in `.internal` or `.local`, and the URL must be at most 256
  characters (`lib/Controller/PushController.php::registerDevice()`). The
  gateway itself speaks plain HTTP and expects a reverse proxy to terminate
  TLS.
- For iOS: an Apple Developer account, an APNs auth key and the app's
  bundle id.
- For Android: a Firebase project and a service account key for it.

At least one provider must be configured; either can be left out.

## Configuration

All configuration is read from environment variables
(`app/config.py`). `.env.example` is an annotated template.

| Variable | Default | Meaning |
| --- | --- | --- |
| `APNS_KEY_PATH` | none | Path to the APNs auth key (`.p8`) as the process sees it. |
| `APNS_KEY_ID` | none | Key ID of that key. |
| `APNS_TEAM_ID` | none | Apple Developer Team ID. |
| `APNS_TOPIC` | `com.nkshub.nextcloudtalk` | Bundle id of the iOS app (OwnTalk's by default). VoIP pushes go to `<topic>.voip`. |
| `APNS_USE_SANDBOX` | `0` | Only for APNs registrations made before clients sent `pushEnvironment`: `1` sends them to the development endpoint, `0` to production. |
| `FCM_PROJECT_ID` | none | Firebase project id the gateway sends through. |
| `FCM_SERVICE_ACCOUNT_PATH` | none | Path to the service account JSON key. |
| `DB_PATH` | `/data/devices.db` | SQLite file. |
| `LISTEN_HOST` | `0.0.0.0` | Bind address of the HTTP server. |
| `LISTEN_PORT` | `8080` | Port of the HTTP server. |
| `NEXTCLOUD_SUBSCRIPTION_KEY` | empty | The `push_subscription_key` of the Nextcloud server, see below. While no key is set, `POST /notifications` answers `401` for everyone and a warning is logged at startup. |
| `NEXTCLOUD_SUBSCRIPTION_KEYS` | empty | Comma-separated keys of further Nextcloud servers using the same gateway. Any listed key is accepted. |
| `TRUSTED_PROXY_IP` | empty | The one peer address whose `X-Forwarded-For` is believed (its last entry only) for rate limiting. Empty means rate limiting uses the TCP peer. |

APNs is enabled when `APNS_KEY_PATH`, `APNS_KEY_ID` and `APNS_TEAM_ID` are
all set; FCM when `FCM_PROJECT_ID` and `FCM_SERVICE_ACCOUNT_PATH` are set.
With neither, the process exits with a configuration error. A device whose
provider is not configured is counted as `failed`, not dropped silently.

`docker-compose.yml` additionally reads `APNS_KEY_HOST_PATH` and
`FCM_SERVICE_ACCOUNT_HOST_PATH` (host paths of the key files, mounted
read-only; unset ones fall back to `/dev/null`) and `BIND_ADDR` (host
address the port is published on, default `127.0.0.1`).

Keys are never passed as environment variables. Keep the `.p8` and the JSON
key outside the repository; `.gitignore` excludes `.env`, `*.p8`, `*.pem`,
`secrets/` and `*service-account*.json`.

## Running

Locally:

```bash
python -m venv .venv
. .venv/bin/activate          # .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt
cp .env.example .env          # fill in, then export the variables
python -m app
python -m pytest
```

`python -m app` does not read `.env` by itself; export the variables or use
Docker Compose, which does.

With Docker Compose:

```bash
cp .env.example .env
$EDITOR .env                  # key ids, topic, host paths of the key files
mkdir -p data && chown 10001:10001 data   # the container runs as uid 10001
docker compose up -d --build
curl http://127.0.0.1:8080/health
```

Put a reverse proxy with a valid certificate in front of it and forward the
public hostname to the published port. If the reverse proxy runs on another
machine, set `BIND_ADDR` to this host's address on the network the proxy
uses (not `0.0.0.0`) and `TRUSTED_PROXY_IP` to the proxy's address. A body
limit of 1 MiB at the proxy matches the gateway's own limit.

The only state is `DB_PATH`. Back it up like any other file. If it is lost,
devices register again the next time the app starts or its push token
changes; until then Nextcloud's pushes to them are answered as `unknown`
(within the rate described under Security notes) and Nextcloud drops its
stale registrations.

## Apple setup

1. In the Apple Developer portal, create a key with the Apple Push
   Notifications service (APNs) capability and download the `.p8`. Note its
   Key ID and your Team ID. One token-based key covers both the development
   and production APNs endpoints and all your apps.
2. Set `APNS_TOPIC` to the app's bundle id. PushKit uses `<bundle id>.voip`;
   no separate certificate is needed for it with token-based auth.
3. The app needs the Push Notifications capability, a Notification Service
   Extension that decrypts `nc-subject`, and, for ringing calls, PushKit and
   the VoIP background mode. That is client work, not gateway work.

Each APNs registration carries `pushEnvironment=development|production`, and
the gateway sends to the matching endpoint (`api.sandbox.push.apple.com` or
`api.push.apple.com`). Debug builds get development tokens; TestFlight and
App Store builds get production tokens. A token sent to the wrong endpoint
comes back as `BadDeviceToken`, the same answer Apple gives for a dead
token.

## Firebase setup

1. Create a Firebase project, or use the one the Android app is built
   against. The FCM token on the phone must come from the same project the
   gateway sends through, so the app's `google-services.json` and
   `FCM_PROJECT_ID` have to match.
2. Make sure the Firebase Cloud Messaging API (V1) is enabled for the
   project.
3. Firebase Console, Project settings, Service accounts: generate a new
   private key. Mount the downloaded JSON read-only and point
   `FCM_SERVICE_ACCOUNT_PATH` at it.

The gateway signs a JWT with that key, exchanges it at
`https://oauth2.googleapis.com/token` for an access token with the
`firebase.messaging` scope, caches it, and calls
`https://fcm.googleapis.com/v1/projects/<project>/messages:send`.

## The Nextcloud side

The server needs the `notifications` app, which ships with Nextcloud and is
enabled by default, and working background jobs (cron), because pushes are
sent from Nextcloud's notification processing. No Nextcloud app has to be
installed for this gateway. `notify_push` is optional; it only adds instant
delivery while the client is running and is unrelated to the gateway.

The push-v2 contract described here was checked against the notifications
app source on the `master` branch and against a running Nextcloud 34
installation. Older releases have not been tested.

Nextcloud sends the `X-Nextcloud-Subscription-Key` header only to the proxy
URL configured as `subscription_aware_server`. The gateway rejects
`/notifications` requests without a known key, so an administrator of each
Nextcloud server that should deliver through it has to run:

```bash
occ config:app:set notifications subscription_aware_server --value="https://push.example.com"
```

After that, Nextcloud generates `push_subscription_key` the first time it
sends a push, and it can be read with:

```bash
occ config:app:get notifications push_subscription_key
```

Put that value into `NEXTCLOUD_SUBSCRIPTION_KEY` (or append it to
`NEXTCLOUD_SUBSCRIPTION_KEYS`) and restart the gateway. The first pushes
before the key is configured are rejected with `401`, and Nextcloud logs
them as failed.

Two consequences follow from how `Push.php` handles this. A server can name
only one `subscription_aware_server`, so it cannot hand its key to two
self-hosted gateways. And once it names this gateway, it stops sending its
Nextcloud Enterprise `subscription_key` to `push-notifications.nextcloud.com`,
which matters on large installations that use the official apps as well.

Independently of all this, Nextcloud checks
`IManager::isFairUseOfFreePushService()` before it contacts any push proxy.
On large installations without an Enterprise subscription it stops sending
to every proxy, including this one.

## Client registration

`POST /devices`, form-urlencoded, after the Nextcloud registration in step 1:

| Field | Meaning |
| --- | --- |
| `pushToken` | The real token: APNs as 64 to 200 lowercase hex characters, FCM as `[A-Za-z0-9_:-]`, 32 to 4096 characters. |
| `pushProvider` | `apns` or `fcm`. |
| `pushEnvironment` | APNs only, required: `development` or `production`. Must be absent for FCM. |
| `deviceIdentifier` | As returned by Nextcloud. |
| `deviceIdentifierSignature` | As returned by Nextcloud. |
| `userPublicKey` | `publicKey` as returned by Nextcloud. RSA, 2048 to 8192 bits. |
| `voipToken` | Optional, APNs only: the PushKit token, different from `pushToken`. |

Answers: `200` with an empty body on success, `400` with
`{"message": "<CODE>"}` for a missing or invalid field or a signature that
does not verify, `403` when the `deviceIdentifier` is already registered
under a different `userPublicKey`, `429` when rate limited.

`DELETE /devices` with `deviceIdentifier` and `deviceIdentifierSignature` in
a form body (never the query string) removes a registration. The signature
is checked against the stored key. It answers `200` whether or not anything
was registered.

The other endpoints are `POST /notifications` (Nextcloud only, described
above) and `GET`/`HEAD /health`, which returns `{"status": "ok", "devices":
<count>}` without authentication.

## Security notes

The registration signature only proves that the caller holds the private
key for `userPublicKey`. `deviceIdentifier` is not secret, so anyone could
sign it with a key of their own. What prevents a takeover is that the first
key registered for a `deviceIdentifier` is pinned: a later registration
under another key gets `403`, in one atomic SQL statement. A token refresh
under the original key is accepted.

What this does not prevent: somebody who learns a `deviceIdentifier` before
its owner registers could register first and block the real device. Doing
that needs values internal to the Nextcloud server. Closing it fully would
require the client to send its user id so the gateway could compare against
Nextcloud's identity-proof endpoint, which the current protocol does not
include.

`POST /notifications` is authenticated twice: by the subscription key, and
per entry by the RSA signature against the pinned key, which only the
Nextcloud server can produce.

The push-v2 format has no nonce or timestamp, so a captured entry could be
replayed. The gateway remembers `(deviceIdentifier, signature)` pairs for
five minutes after a successful send and drops repeats; the memory holds at
most 16,384 entries. This limits replays; it cannot remove them, and
Nextcloud's own proxy has the same exposure.

Other limits in `app/server.py`: request bodies over 1 MiB get `413`; a
negative or non-numeric `Content-Length` gets `400`; each connection has a
10-second socket timeout; `/devices` is limited to 20 requests per minute
per client address and `/notifications` to 120; a batch is capped at 100
entries; `subject` must be exactly the length of an RSA-2048 ciphertext; at
most 10 devices per hour, across all servers, are reported to Nextcloud as
`unknown` (unregistered here or declared dead by the provider), and beyond
that they count as `failed`. The last rule exists because Apple answers a
token sent to the wrong environment the same way as a dead one, and a
misconfiguration or a lost database should not wipe every registration on
the Nextcloud side at once.

Nothing limits how many devices can be registered. Each row costs the
caller an RSA key pair, not more; watch disk usage and the `/health` device
count if that becomes a concern.

## Operations

Logs go to stdout with UTC timestamps. Each `POST /notifications` logs its
outcome per entry. `APNs push failed: status=... reason=...` gives Apple's
reason: `BadDeviceToken` is a dead token or an environment mismatch,
`BadTopic` a wrong `APNS_TOPIC`, `InvalidProviderToken` a wrong Key ID or
Team ID or a revoked key. FCM failures log the HTTP status and FCM error
code; a failing OAuth exchange points at the service account key, the
project or the clock rather than at device tokens. Behind a reverse proxy,
the access log shows the proxy's address, not the client's.

To rotate the APNs key, create a new key, mount it, update `APNS_KEY_ID` and
the key path, restart, confirm a real notification arrives, then revoke the
old key. The FCM service account key rotates the same way. Clients need no
change in either case.

When notifications do not arrive, check in this order: `GET /health`
through the public URL; whether the device count grows when a phone
registers; whether Nextcloud posts to the gateway at all (nothing in the
gateway log usually means `subscription_aware_server` or the key is missing,
cron is not running, or the client registered a different `proxyServer`;
Nextcloud logs `Could not send notification to push server` with the
gateway's answer); then the provider errors above.

When testing against a live gateway, register synthetic devices with a
preimage that no real registration can produce (for example a
`SMOKETEST:` prefix, see `make_fake_device()` in `tests/conftest.py`) and
delete them in the same script, so they do not linger in the device count.

## Limitations

- One process, one SQLite file. Not built for horizontal scaling.
- No retry queue. A push that fails at the provider is reported to
  Nextcloud as `failed`; Nextcloud logs it and does not resend it.
- The first-registration squatting gap described above.
- Registrations made before clients sent `pushProvider` are routed by token
  shape, and APNs ones of them by `APNS_USE_SANDBOX`.
- Tested with OwnTalk as the only client.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests use generated keys and fake provider responses; they do not
contact Apple or Google.

## License

GPL-3.0-or-later, the same as OwnTalk. See [LICENSE](LICENSE).
