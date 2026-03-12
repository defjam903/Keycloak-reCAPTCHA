package com.example.keycloak.recaptcha;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Keycloak reCAPTCHA Login Authenticator
 *
 * <p>Extends the built-in {@link UsernamePasswordForm} to inject Google reCAPTCHA v2
 * validation into the browser login flow. The reCAPTCHA token is verified against
 * Google's siteverify API before credentials are checked, blocking bot-driven
 * brute-force attacks at the earliest possible point.</p>
 *
 * <p><b>Deployment:</b> Copy the plugin JAR to {@code $KEYCLOAK_HOME/providers/},
 * then run {@code bin/kc.sh build}. See README.md for full setup instructions.</p>
 */
public class RecaptchaLoginAuthenticator extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(RecaptchaLoginAuthenticator.class);

    /** Google's reCAPTCHA token form field name (injected by the JS widget). */
    static final String RECAPTCHA_RESPONSE_FIELD = "g-recaptcha-response";

    /** Google siteverify endpoint. */
    private static final String GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    /** Minimum score to accept for reCAPTCHA v3 (unused in v2, kept for future use). */
    private static final double MIN_SCORE = 0.5;

    // -----------------------------------------------------------------------
    // Core flow entry points
    // -----------------------------------------------------------------------

    /**
     * Called when the browser first hits the login page (GET).
     * Renders the login form with reCAPTCHA attributes injected.
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String siteKey = getSiteKey(context);
        if (siteKey == null || siteKey.isBlank()) {
            logger.warn("[reCAPTCHA] Site key is not configured — rendering login form WITHOUT reCAPTCHA");
            super.authenticate(context);
            return;
        }
        Response response = buildLoginForm(context, siteKey).createLoginUsernamePassword();
        context.challenge(response);
    }

    /**
     * Called when the user submits the login form (POST).
     * Validates the reCAPTCHA token first; only proceeds to credential check on success.
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String siteKey = getSiteKey(context);
        if (siteKey == null || siteKey.isBlank()) {
            // Plugin not configured — fall through to normal login
            logger.warn("[reCAPTCHA] Site key not configured, skipping reCAPTCHA check");
            super.action(context);
            return;
        }

        String recaptchaToken = formData.getFirst(RECAPTCHA_RESPONSE_FIELD);
        if (recaptchaToken == null || recaptchaToken.isBlank()) {
            logger.warn("[reCAPTCHA] No reCAPTCHA token in form submission — rejecting");
            renderChallengeWithError(context, siteKey, "recaptchaRequired");
            return;
        }

        String secretKey = getSecretKey(context);
        if (secretKey == null || secretKey.isBlank()) {
            logger.error("[reCAPTCHA] Secret key is not configured — cannot verify token");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        boolean verified = verifyRecaptchaToken(recaptchaToken, secretKey, context);
        if (!verified) {
            logger.warn("[reCAPTCHA] Token verification failed — rejecting login attempt");
            renderChallengeWithError(context, siteKey, "recaptchaFailed");
            return;
        }

        logger.debug("[reCAPTCHA] Token verified successfully — proceeding to credential check");
        super.action(context);
    }

    // -----------------------------------------------------------------------
    // reCAPTCHA verification
    // -----------------------------------------------------------------------

    /**
     * Calls Google's siteverify API and returns {@code true} if the token is valid.
     *
     * @param token     the {@code g-recaptcha-response} value from the form
     * @param secretKey the configured reCAPTCHA secret key
     * @param context   the Keycloak authentication flow context
     * @return {@code true} on successful verification
     */
    private boolean verifyRecaptchaToken(String token, String secretKey, AuthenticationFlowContext context) {
        try {
            // Build POST body
            String postData = "secret=" + URLEncoder.encode(secretKey, StandardCharsets.UTF_8)
                    + "&response=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

            // Optionally include the user's remote IP for additional Google-side signals
            String remoteAddr = context.getConnection().getRemoteAddr();
            if (remoteAddr != null && !remoteAddr.isBlank()) {
                postData += "&remoteip=" + URLEncoder.encode(remoteAddr, StandardCharsets.UTF_8);
            }

            // Execute the HTTP POST
            URL url = new URL(GOOGLE_VERIFY_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5_000);
            conn.setReadTimeout(5_000);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Content-Length", String.valueOf(postData.length()));

            try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
                out.writeBytes(postData);
                out.flush();
            }

            int status = conn.getResponseCode();
            if (status != 200) {
                logger.errorf("[reCAPTCHA] Google API returned HTTP %d", status);
                return false;
            }

            // Read response body
            StringBuilder responseBody = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBody.append(line);
                }
            }

            String body = responseBody.toString();
            logger.debugf("[reCAPTCHA] Siteverify response: %s", body);

            // Parse "success": true/false without pulling in a JSON library
            return parseSuccess(body);

        } catch (Exception e) {
            logger.errorf(e, "[reCAPTCHA] Exception during token verification");
            return false;
        }
    }

    /**
     * Lightweight JSON success-field parser — avoids adding a JSON dependency.
     * Looks for {@code "success":true} (with optional whitespace).
     */
    static boolean parseSuccess(String json) {
        if (json == null) return false;
        // Normalize and search for the success field
        String normalized = json.replaceAll("\\s", "");
        return normalized.contains("\"success\":true");
    }

    // -----------------------------------------------------------------------
    // Form helpers
    // -----------------------------------------------------------------------

    /**
     * Builds the login form with reCAPTCHA site key and any error message injected
     * as FreeMarker attributes.
     */
    private LoginFormsProvider buildLoginForm(AuthenticationFlowContext context, String siteKey) {
        return context.form()
                .setAttribute("recaptchaRequired", true)
                .setAttribute("recaptchaSiteKey", siteKey);
    }

    /**
     * Re-renders the login page with an error message after reCAPTCHA failure.
     *
     * @param messageKey a key defined in {@code messages_en.properties} of your theme
     */
    private void renderChallengeWithError(AuthenticationFlowContext context,
                                          String siteKey,
                                          String messageKey) {
        Response challenge = buildLoginForm(context, siteKey)
                .setError(messageKey)
                .createLoginUsernamePassword();
        context.challenge(challenge);
    }

    // -----------------------------------------------------------------------
    // Configuration accessors
    // -----------------------------------------------------------------------

    private String getSiteKey(AuthenticationFlowContext context) {
        return context.getAuthenticatorConfig() != null
                ? context.getAuthenticatorConfig().getConfig()
                         .get(RecaptchaLoginAuthenticatorFactory.CONFIG_SITE_KEY)
                : null;
    }

    private String getSecretKey(AuthenticationFlowContext context) {
        return context.getAuthenticatorConfig() != null
                ? context.getAuthenticatorConfig().getConfig()
                         .get(RecaptchaLoginAuthenticatorFactory.CONFIG_SECRET_KEY)
                : null;
    }
}
