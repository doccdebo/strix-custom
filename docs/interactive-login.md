# Interactive Login

Strix supports **interactive browser login** for web applications that require
manual authentication — including multi-factor authentication (MFA), CAPTCHA,
OAuth/SAML flows, or any business-specific login logic.

---

## How It Works

```
strix --target https://app.com --enable-interactive-login
                │
    ┌───────────▼────────────────┐
    │  Launch Managed Browser    │  Chrome / Firefox / Edge
    │  + Proxy Interception      │  127.0.0.1:8888 (default)
    └───────────┬────────────────┘
                │
    ┌───────────▼────────────────────────────────┐
    │  TUI: Wait for Login                       │
    │  Browser URL: http://localhost:9222        │
    │                                            │
    │  [C] Continue  [S] Skip  [Q] Quit          │
    └───────────┬────────────────────────────────┘
                │
    ┌───────────▼──────────────────────┐
    │  Capture Session                 │
    │  - Cookies (JSESSIONID, etc.)    │
    │  - Auth headers (Authorization)  │
    │  - JWT tokens                    │
    └───────────┬──────────────────────┘
                │
    ┌───────────▼──────────────────────────────────┐
    │  Resume Strix Agents with Authenticated       │
    │  Session injected into all HTTP requests      │
    └───────────────────────────────────────────────┘
```

---

## Supported Browsers

Strix auto-detects installed browsers in the following order of preference:

| Browser | Executables detected |
|---------|----------------------|
| Chrome  | `google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` |
| Firefox | `firefox`, `firefox-esr` |
| Edge    | `msedge`, `microsoft-edge`, `microsoft-edge-stable` |
| Safari  | macOS only — `/Applications/Safari.app/…` |

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-interactive-login` | off | Launch a managed browser for manual authentication |
| `--browser` | `auto` | Browser to use: `auto`, `chrome`, `firefox`, `edge`, `safari` |
| `--login-timeout` | `300` | Seconds to wait for an authenticated session |

---

## Quick Start

### Basic usage

```bash
export STRIX_LLM="openai/gpt-4"
export LLM_API_KEY="sk-..."

strix --target https://your-app.com --enable-interactive-login
```

1. A browser window opens.
2. Navigate to `https://your-app.com` and log in manually.
3. Press **C** in the terminal (or TUI) once you're logged in.
4. Strix captures your session cookies and resumes testing.

### With MFA / CAPTCHA

```bash
strix --target https://your-app.com --enable-interactive-login --login-timeout 600
```

The extended timeout gives you 10 minutes to complete complex auth flows.

### Specify browser explicitly

```bash
strix --target https://your-app.com --enable-interactive-login --browser firefox
```

### Keep the browser open after login

```bash
STRIX_KEEP_BROWSER=1 strix --target https://your-app.com --enable-interactive-login
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIX_INTERACTIVE_LOGIN` | `0` | Enable interactive login without CLI flag |
| `STRIX_BROWSER` | `auto` | Browser preference |
| `STRIX_LOGIN_TIMEOUT` | `300` | Timeout in seconds |
| `STRIX_LOGIN_PROXY_PORT` | `8888` | Local proxy port for traffic interception |
| `STRIX_KEEP_BROWSER` | `0` | Keep browser open after session capture |

---

## Session Detection

Strix automatically detects an authenticated session when it observes **any** of:

- A known session cookie (`JSESSIONID`, `PHPSESSID`, `connect.sid`, `session`, …)
- An `Authorization`, `X-Auth-Token`, `X-Access-Token`, or similar header
- A JWT token in a request header or response body

You can also **manually confirm** the session by pressing **C** in the TUI, even
if auto-detection has not triggered yet (e.g., after completing MFA).

---

## TUI Interface

```
┌────────────────────────────────────────────────────────────┐
│                   INTERACTIVE LOGIN                        │
├────────────────────────────────────────────────────────────┤
│  Browser URL: http://localhost:9222                       │
│  Target: https://your-app.com                             │
│                                                            │
│  No session detected yet (30s / 300s)                     │
│                                                            │
│  Traffic: 45 requests captured  |  Cookies: 0 found       │
│                                                            │
│  [C] Continue (session detected)                          │
│  [S] Skip auth (continue unauthenticated)                 │
│  [Q] Quit                                                 │
└────────────────────────────────────────────────────────────┘
```

---

## Security

- **Session data is kept in memory** — never written to disk.
- **Isolated browser profile** — Strix launches the browser with a fresh
  temporary profile so none of your personal browser data is accessible.
- **Transparent proxy** — the intercepting proxy observes traffic but never
  modifies requests or responses.
- **Automatic cleanup** — the temporary profile directory is deleted when the
  scan completes (unless `STRIX_KEEP_BROWSER=1`).

---

## Combining with `--instruction`

Interactive login and `--instruction` can be combined:

```bash
strix --target https://app.com \
      --enable-interactive-login \
      --instruction "After login, also test with admin credentials: admin:password"
```

Strix will use your manually captured session for initial authenticated testing
and the provided credentials for privilege-escalation attempts.

---

## Troubleshooting

### Browser won't launch

- Ensure Chrome, Firefox, or Edge is installed and on your `$PATH`.
- On macOS, grant Terminal accessibility permissions if prompted.
- Try specifying the browser explicitly: `--browser chrome`.

### Session not detected

- Make sure you complete the full login flow (including MFA) before pressing **C**.
- Check that the application uses standard cookies or `Authorization` headers.
- For applications using non-standard auth mechanisms, press **C** manually
  after logging in — Strix will use whatever session data was captured.

### Proxy port conflict

Set a different port:

```bash
STRIX_LOGIN_PROXY_PORT=9999 strix --target https://app.com --enable-interactive-login
```

### Timeout too short

```bash
strix --target https://app.com --enable-interactive-login --login-timeout 900
```
