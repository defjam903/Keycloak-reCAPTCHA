package com.example.keycloak.recaptcha;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

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

    /** Maximum number of attempts to reach Google's API (1 initial + 2 retries). */
    private static final int MAX_ATTEMPTS = 3;

    /** Base delay in milliseconds for exponential back-off between retries. */
    private static final long RETRY_BASE_DELAY_MS = 300;

    /**
     * Shared, thread-safe {@link HttpClient} with built-in connection pooling.
     * A single instance is reused across all login requests.
     * Redirects are disabled — Google's siteverify endpoint should never redirect,
     * and following redirects to an unexpected host would be a security risk.
     */
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

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
     * Calls Google's siteverify API with up to {@value MAX_ATTEMPTS} attempts.
     * Transient failures (network errors, HTTP 5xx) are retried with exponential
     * back-off. Permanent failures (HTTP 4xx) are not retried.
     *
     * @param token     the {@code g-recaptcha-response} value from the form
     * @param secretKey the configured reCAPTCHA secret key
     * @param context   the Keycloak authentication flow context
     * @return {@code true} on successful verification
     */
    private boolean verifyRecaptchaToken(String token, String secretKey, AuthenticationFlowContext context) {
        String postBody = buildPostBody(token, secretKey, context);
        HttpRequest request = buildHttpRequest(postBody);

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> response =
                        HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                int status = response.statusCode();
                if (status == 200) {
                    String body = response.body();
                    logger.debugf("[reCAPTCHA] Siteverify response (attempt %d): %s", attempt, body);
                    return parseSuccess(body);
                }

                // 4xx = permanent failure (bad request / unauthorized) — do not retry
                if (status >= 400 && status < 500) {
                    logger.errorf("[reCAPTCHA] Google API returned HTTP %d — not retrying", status);
                    return false;
                }

                // 5xx = transient server-side error — fall through to retry logic below
                logger.warnf("[reCAPTCHA] Google API returned HTTP %d on attempt %d/%d",
                        status, attempt, MAX_ATTEMPTS);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("[reCAPTCHA] Thread interrupted during token verification");
                return false;
            } catch (IOException e) {
                // Network/IO error — transient, fall through to retry
                logger.warnf(e, "[reCAPTCHA] Network error on attempt %d/%d", attempt, MAX_ATTEMPTS);
            }

            if (attempt < MAX_ATTEMPTS) {
                sleepBeforeRetry(attempt);
            }
        }

        logger.errorf("[reCAPTCHA] All %d attempts to verify token failed", MAX_ATTEMPTS);
        return false;
    }

    /**
     * Builds the URL-encoded POST body for the siteverify request.
     * Using {@link URLEncoder#encode(String, java.nio.charset.Charset)} ensures
     * correct byte-level encoding — the body publisher below measures byte length,
     * not character length, so {@code Content-Length} will always be accurate.
     */
    private String buildPostBody(String token, String secretKey, AuthenticationFlowContext context) {
        StringBuilder sb = new StringBuilder();
        sb.append("secret=").append(URLEncoder.encode(secretKey, StandardCharsets.UTF_8));
        sb.append("&response=").append(URLEncoder.encode(token, StandardCharsets.UTF_8));

        // Optionally include the user's remote IP for additional Google-side signals
        String remoteAddr = context.getConnection().getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isBlank()) {
            sb.append("&remoteip=").append(URLEncoder.encode(remoteAddr, StandardCharsets.UTF_8));
        }

        return sb.toString();
    }

    /**
     * Builds an immutable {@link HttpRequest}. Because the body is constant across
     * retry attempts, the same request object is reused for all attempts.
     * {@link HttpRequest.BodyPublishers#ofString} encodes to UTF-8 bytes and sets
     * {@code Content-Length} to the correct byte count (fixing the character-count
     * bug present in the previous {@code DataOutputStream.writeBytes} approach).
     */
    private HttpRequest buildHttpRequest(String postBody) {
        return HttpRequest.newBuilder()
                .uri(URI.create(GOOGLE_VERIFY_URL))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(postBody, StandardCharsets.UTF_8))
                .build();
    }

    /** Sleeps for {@code RETRY_BASE_DELAY_MS * 2^(attempt-1)} ms (300 ms, then 600 ms). */
    private void sleepBeforeRetry(int attempt) {
        long delayMs = RETRY_BASE_DELAY_MS * (1L << (attempt - 1));
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
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
