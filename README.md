# Keycloak reCAPTCHA Login Authenticator

A Keycloak SPI plugin that adds **Google reCAPTCHA v2** ("I'm not a robot") to the browser **login** flow — a capability Keycloak provides natively only for the registration flow.

---

## How It Works

```
Browser GET /login
  └─► Keycloak renders login.ftl (with reCAPTCHA widget injected)

User fills username + password + solves reCAPTCHA → POST /login
  └─► RecaptchaLoginAuthenticator.action()
        ├─ Extracts g-recaptcha-response token
        ├─ POSTs token to https://www.google.com/recaptcha/api/siteverify
        ├─ On failure → re-renders form with error message
        └─ On success → calls super.action() (standard credential check)
```

The plugin **extends** `UsernamePasswordForm` — so all existing username/password, brute-force protection, and post-login redirect logic is preserved.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Java | 11+ |
| Maven | 3.8+ |
| Keycloak | 22+ (Quarkus-based) |

> **Note:** Adjust `<keycloak.version>` in `pom.xml` to match your exact Keycloak server version.

---

## Step 1 — Get reCAPTCHA Keys

1. Go to [https://www.google.com/recaptcha/admin](https://www.google.com/recaptcha/admin)
2. Create a new site:
   - **Label**: anything descriptive (e.g. `My App Login`)
   - **reCAPTCHA type**: **v2 → "I'm not a robot" Checkbox**
   - **Domains**: add your Keycloak hostname (e.g. `auth.myapp.com`)
     - Add `localhost` for local development
3. Copy the **Site Key** (public) and **Secret Key** (private)

---

## Step 2 — Build the Plugin

```bash
git clone <this-repo>
cd keycloak-recaptcha-login
mvn clean package -DskipTests
```

This produces:

```
target/keycloak-recaptcha-login-1.0.0.jar
```

---

## Step 3 — Deploy the JAR

### Standalone / Docker

```bash
# Copy the JAR to Keycloak's providers directory
cp target/keycloak-recaptcha-login-1.0.0.jar $KEYCLOAK_HOME/providers/

# Rebuild Keycloak to register the new provider
$KEYCLOAK_HOME/bin/kc.sh build

# Start Keycloak
$KEYCLOAK_HOME/bin/kc.sh start
```

### Docker Compose

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0.0
    volumes:
      - ./target/keycloak-recaptcha-login-1.0.0.jar:/opt/keycloak/providers/keycloak-recaptcha-login.jar
      # Mount the custom theme
      - ./src/main/resources/theme/recaptcha-login:/opt/keycloak/themes/recaptcha-login
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://db/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
```

### Kubernetes / Operator

Add an init container or a ConfigMap-based volume mount to place the JAR in `/opt/keycloak/providers/` before Keycloak starts.

---

## Step 4 — Deploy the Custom Theme

The custom `login.ftl` template renders the reCAPTCHA widget. Copy the theme directory:

```bash
cp -r src/main/resources/theme/recaptcha-login $KEYCLOAK_HOME/themes/
```

Or mount it via Docker volume as shown above.

---

## Step 5 — Configure in the Admin Console

### 5a. Set the Login Theme

1. Admin Console → **Your Realm** → **Realm Settings** → **Themes**
2. Set **Login Theme** to `recaptcha-login`
3. Click **Save**

### 5b. Update Content Security Policy

Google's reCAPTCHA runs in an iframe. You must allow it:

1. Admin Console → **Realm Settings** → **Security Defenses**
2. Update the headers:

| Header | Value to add |
|---|---|
| `X-Frame-Options` | `ALLOW-FROM https://www.google.com` |
| `Content-Security-Policy` | add `frame-src 'self' https://www.google.com;` and `script-src 'self' https://www.google.com` |

Example full CSP value:
```
frame-src 'self' https://www.google.com; frame-ancestors 'self'; object-src 'none'; script-src 'self' https://www.google.com;
```

### 5c. Create a New Browser Flow with reCAPTCHA

1. Admin Console → **Authentication** → **Flows**
2. Select the **Browser** flow → click **Action** → **Duplicate**
3. Name it e.g. `Browser with reCAPTCHA`
4. In the new flow, find **Browser Forms** → expand it
5. **Delete** the `Username Password Form` execution
6. Click **Add Step** inside **Browser Forms**
7. Search for and select: **`Username Password Form with reCAPTCHA`**
8. Set its requirement to **REQUIRED**
9. Click the **⚙️ gear icon** (Settings) next to the new execution
10. Enter your **reCAPTCHA Site Key** and **Secret Key**
11. Click **Save**

### 5d. Bind the New Flow

1. Admin Console → **Authentication** → **Bindings**
2. Set **Browser Flow** to `Browser with reCAPTCHA`
3. Click **Save**

---

## Verification

1. Open your realm's login page in a browser
2. You should see the reCAPTCHA "I'm not a robot" checkbox
3. Try submitting without completing it — you should see an error
4. Complete the reCAPTCHA and log in normally

---

## Project Structure

```
keycloak-recaptcha-login/
├── pom.xml
├── README.md
└── src/main/
    ├── java/com/example/keycloak/recaptcha/
    │   ├── RecaptchaLoginAuthenticator.java        # Core logic
    │   └── RecaptchaLoginAuthenticatorFactory.java # SPI registration
    └── resources/
        ├── META-INF/services/
        │   └── org.keycloak.authentication.AuthenticatorFactory  # ServiceLoader
        └── theme/recaptcha-login/login/
            ├── login.ftl                           # Login page with widget
            ├── theme.properties                    # Inherits from 'keycloak' theme
            └── messages/
                └── messages_en.properties          # Error strings
```

---

## Customization

### Switching to reCAPTCHA v3 (Invisible)

reCAPTCHA v3 uses a score (0.0–1.0) rather than a checkbox. The server-side verification response includes a `score` field. To support v3:

1. Change the widget script URL and `data-` attributes in `login.ftl` to use the v3 API
2. In `RecaptchaLoginAuthenticator.verifyRecaptchaToken()`, parse the `score` field from the JSON response and compare it against a threshold (e.g. `>= 0.5`)

### Adding reCAPTCHA to Other Flows

The same JAR can be referenced in the **Reset Credentials** or **Registration** flows. Create additional execution steps and configure separate site/secret keys as needed.

### Customizing Error Messages

Edit `src/main/resources/theme/recaptcha-login/login/messages/messages_en.properties` for additional languages or adjusted wording.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| reCAPTCHA widget does not render | Wrong site key, or CSP blocking Google scripts | Check browser console for CSP errors; update Security Defenses headers |
| "reCAPTCHA verification failed" on every login | Wrong secret key | Verify the secret key matches your Google reCAPTCHA admin registration |
| Provider not visible in Admin Console | JAR not copied / `kc build` not run | Re-copy JAR, run `kc.sh build`, restart Keycloak |
| Login works without reCAPTCHA | Flow not bound, or old flow still active | Check Authentication → Bindings → Browser Flow |
| `recaptchaRequired` message not shown | Theme not set | Check Realm Settings → Themes → Login Theme = `recaptcha-login` |

---

## Security Notes

- **The secret key is never exposed to the browser.** It is stored in the Keycloak authenticator config and only used in server-side API calls.
- The client-side validation in `login.ftl` is a UX convenience only. The server **always** re-validates the token.
- reCAPTCHA tokens are single-use and expire after ~2 minutes.
- Google receives the user's IP address as part of verification (controlled by the `remoteip` parameter).

---

## License

MIT — free to use, modify, and distribute.
