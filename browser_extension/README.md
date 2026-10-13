# webchallscan Session Bridge

Chromium MV3 companion extension for importing the current challenge tab into a
local `webchallscan` one-shot listener. The extension sends the exact active URL
and cookies visible to that URL, including `HttpOnly` cookies exposed through
`chrome.cookies`.

The extension uses its own `0.1.0` version. It does not track the CLI package
version.

## Security contract

- The user must open the popup and click **Capture active tab**.
- `activeTab` grants temporary access only to the tab selected by that click.
- `scripting` reads only that tab's user agent and language under the temporary
  `activeTab` grant.
- Network access is limited by the manifest to `http://127.0.0.1/*` and
  `http://localhost/*`.
- The listener URL must contain an explicit port and the exact path
  `/v1/session/import`.
- Every request requires a 32-256 character base64url one-shot token in the
  `X-Webchallscan-Token` header.
- The extension uses no storage API, analytics, remote script, or remote service.
- The popup clears the token after each attempt. The service worker does not log
  the URL, token, or cookies.

Cookies are credentials. Use the bridge only with CTF targets you are authorized
to test. Close the listener after one accepted request.

## Load in Chromium

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose this `browser_extension` directory.

## Capture flow

1. Start the `webchallscan` browser-session listener. It prints a loopback URL
   and a random one-shot token.
2. Keep the intended challenge page active.
3. Open the extension popup.
4. Paste the listener URL and token.
5. Click **Capture active tab**.

The listener receives deterministic JSON for the same tab and cookie state:

```json
{
  "schema": "webchallscan/browser-session-v1",
  "active_tab": {
    "url": "https://challenge.example/account",
    "origin": "https://challenge.example",
    "incognito": false
  },
  "browser": {
    "user_agent": "Mozilla/5.0 ...",
    "accept_language": "en-US",
    "platform": "Win32",
    "mobile": false
  },
  "cookies": [
    {
      "name": "session",
      "value": "secret-value",
      "domain": "challenge.example",
      "path": "/",
      "secure": true,
      "http_only": true,
      "same_site": "lax",
      "session": true,
      "expiration_date": null,
      "store_id": "0",
      "partition_key": null
    }
  ]
}
```

The extension identifies the cookie store that owns the active tab, then sorts
cookies by store, domain, path, name, and partition key. It adds no timestamp or
random field. The popup reports only success or failure. It does not display the
URL, user agent, cookie names, or values. The local listener
must validate the schema, token, body size, exact origin scope, and duplicate
cookie names before scanning.

## Limits

- Chromium may hide cookies that belong to an inaccessible profile or store.
- Enable the extension in Incognito mode if the challenge session runs there.
- The bridge captures browser state. It does not execute challenge actions or
  bypass browser security controls.
