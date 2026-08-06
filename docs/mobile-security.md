# Mobile Security Testing with MobSF

Strix integrates with [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) to perform static analysis on Android APK and iOS IPA binaries.  After analysis, any backend URLs and API routes discovered inside the binary are automatically fed into Strix's web / API scanning pipeline.

---

## Running MobSF Locally with Docker

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest

docker run -it --rm \
  -p 8000:8000 \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF will be available at `http://localhost:8000`.  The REST API key is displayed in the container startup logs — look for a line like:

```
REST API Key: <your-api-key>
```

---

## Required Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MOBSF_URL` | `http://localhost:8000` | Base URL of your MobSF instance |
| `MOBSF_API_KEY` | *(required)* | REST API key printed in MobSF logs |
| `MOBSF_TIMEOUT` | `120` | HTTP request timeout in seconds |

Export them before running Strix:

```bash
export MOBSF_URL=http://localhost:8000
export MOBSF_API_KEY=<your-api-key>
```

---

## CLI Usage

### APK analysis only

```bash
strix --target-apk ./app-release.apk
```

Strix will upload the APK to MobSF, wait for the static analysis report, and then scan every discovered backend URL.

### APK analysis + known backend

```bash
strix --target-apk ./app-release.apk --target https://api.myapp.com
```

Any URLs found in the APK are added to the target list alongside the explicit `--target` value (deduplication is applied automatically).

### Non-interactive (CI) mode

```bash
strix --target-apk ./app-release.apk --non-interactive
```

---

## How the Pipeline Works

1. **Upload** – the binary is uploaded to MobSF via `POST /api/v1/upload`.
2. **Scan** – static analysis is triggered via `POST /api/v1/scan`.
3. **Poll** – Strix polls `POST /api/v1/report_json` until the report is ready (up to 5 minutes by default).
4. **Parse** – the JSON report is parsed to extract:
   - Hardcoded secrets / API keys
   - Insecure HTTP endpoints
   - Weak cryptography usage (MD5, SHA1, DES, RC2, ECB)
   - Misconfigured network security config
5. **Inject** – every discovered URL and API route is added to the Strix target queue as a `web_application` entry.
6. **Summarise** – a MobSF findings summary is prepended to the Strix agent's instructions so the agent is aware of the mobile-specific context.

---

## Troubleshooting

### MobSF is offline

If MobSF is unreachable and additional `--target` values were provided, Strix logs a warning and continues with the original targets.  If `--target-apk` is the *only* target source, Strix exits with an error.

```
WARNING  strix.mobile.pipeline – MobSF is offline – continuing with original targets.
```

Start MobSF (see above) and re-run.

### File not found

```
Error: APK/IPA file not found: ./app-release.apk
```

Double-check the path passed to `--target-apk`.

### Missing API key

```
Error: MOBSF_API_KEY is not set. Configure your MobSF instance and set MOBSF_API_KEY.
```

Set `MOBSF_API_KEY` to the value shown in the MobSF container logs.

### Report takes too long

By default Strix polls for up to 30 × 10 s = 5 minutes.  For very large binaries, start MobSF on a machine with more CPU/memory.
