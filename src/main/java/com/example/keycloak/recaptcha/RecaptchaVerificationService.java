package com.example.keycloak.recaptcha;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Encapsulates all network communication with Google's reCAPTCHA siteverify API.
 *
 * <p>Uses the {@link CloseableHttpClient} supplied by Keycloak's
 * {@code HttpClientProvider}, which is centrally managed by the Keycloak runtime:
 * it handles connection pooling, TLS configuration, proxy settings, and
 * respects any JVM-wide networking properties configured by the operator.</p>
 *
 * <p>The service is stateless beyond the injected client reference and is safe
 * to share across threads. A fresh instance is created per Keycloak session by
 * {@link RecaptchaLoginAuthenticatorFactory#create}, so the client is always
 * the one that was active when the session was opened.</p>
 */
class RecaptchaVerificationService {

    private static final Logger logger = Logger.getLogger(RecaptchaVerificationService.class);

    static final String GOOGLE_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    /** Total call attempts: 1 initial + 2 retries. */
    private static final int MAX_ATTEMPTS = 3;

    /** Base back-off delay in milliseconds; doubles on each subsequent retry. */
    private static final long RETRY_BASE_DELAY_MS = 300;

    private final CloseableHttpClient httpClient;

    /**
     * @param httpClient the Keycloak-managed Apache HTTP client — must not be {@code null}.
     *                   Do <em>not</em> close this client; its lifecycle is owned by Keycloak.
     */
    RecaptchaVerificationService(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Calls Google's siteverify endpoint and returns {@code true} if the token is valid.
     * Transient failures (network errors, HTTP 5xx) are retried with exponential back-off.
     * Permanent failures (HTTP 4xx) are not retried.
     *
     * @param token      the {@code g-recaptcha-response} value from the login form
     * @param secretKey  the configured reCAPTCHA secret key
     * @param remoteAddr the end-user's IP address, or {@code null} to omit
     * @return {@code true} on successful verification
     */
    boolean verify(String token, String secretKey, String remoteAddr) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpPost post = buildPost(token, secretKey, remoteAddr);

                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    int status = response.getStatusLine().getStatusCode();

                    if (status == 200) {
                        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                        logger.debugf("[reCAPTCHA] Siteverify response (attempt %d): %s", attempt, body);
                        boolean success = parseSuccess(body);
                        if (!success) {
                            logVerificationFailure(body);
                        }
                        return success;
                    }

                    // Consume entity so the connection is returned to the pool cleanly
                    EntityUtils.consumeQuietly(response.getEntity());

                    // 4xx = permanent failure (bad request / unauthorized) — do not retry
                    if (status >= 400 && status < 500) {
                        logger.errorf("[reCAPTCHA] Google API returned HTTP %d — not retrying", status);
                        return false;
                    }

                    // 5xx = transient server error — fall through to retry
                    logger.warnf("[reCAPTCHA] Google API returned HTTP %d on attempt %d/%d",
                            status, attempt, MAX_ATTEMPTS);
                }

            } catch (IOException e) {
                // Network/IO error — transient, retry
                logger.warnf(e, "[reCAPTCHA] Network error on attempt %d/%d", attempt, MAX_ATTEMPTS);
            }

            if (attempt < MAX_ATTEMPTS) {
                sleepBeforeRetry(attempt);
            }
        }

        logger.errorf("[reCAPTCHA] All %d attempts to verify token failed", MAX_ATTEMPTS);
        return false;
    }

    // -----------------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------------

    /**
     * Builds a new {@link HttpPost} for each attempt.
     * {@link UrlEncodedFormEntity} handles URL encoding and sets
     * {@code Content-Type: application/x-www-form-urlencoded} with the correct byte-length.
     */
    private HttpPost buildPost(String token, String secretKey, String remoteAddr) throws IOException {
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("secret", secretKey));
        params.add(new BasicNameValuePair("response", token));
        if (remoteAddr != null && !remoteAddr.isBlank()) {
            params.add(new BasicNameValuePair("remoteip", remoteAddr));
        }
        HttpPost post = new HttpPost(GOOGLE_VERIFY_URL);
        post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        return post;
    }

    private void sleepBeforeRetry(int attempt) {
        long delayMs = RETRY_BASE_DELAY_MS * (1L << (attempt - 1));
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // -----------------------------------------------------------------------
    // Response parsing and diagnostic logging
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} when Google's response contains {@code "success":true}.
     * Whitespace is normalised before matching to tolerate minor formatting variations.
     */
    static boolean parseSuccess(String json) {
        if (json == null) return false;
        return json.replaceAll("\\s", "").contains("\"success\":true");
    }

    /**
     * Logs a detailed, actionable message when Google returns {@code "success":false}.
     *
     * <p>Three distinct cases are handled:
     * <ol>
     *   <li>The {@code success} field is absent — likely an API format change; logged at ERROR.</li>
     *   <li>Google returns {@code error-codes} — each code is logged individually:
     *       ERROR for configuration problems requiring admin action,
     *       WARN for expected user-side failures.</li>
     *   <li>{@code success:false} with no {@code error-codes} — raw body logged at WARN.</li>
     * </ol>
     */
    private void logVerificationFailure(String responseBody) {
        String normalized = responseBody == null ? "" : responseBody.replaceAll("\\s", "");

        if (!normalized.contains("\"success\":")) {
            logger.errorf("[reCAPTCHA] Unexpected response format — 'success' field missing. "
                    + "Google may have changed their API. Raw response: %s", responseBody);
            return;
        }

        List<String> errorCodes = extractErrorCodes(responseBody);
        if (errorCodes.isEmpty()) {
            logger.warnf("[reCAPTCHA] Verification returned success:false with no error-codes. "
                    + "Raw response: %s", responseBody);
            return;
        }

        for (String code : errorCodes) {
            switch (code) {
                case "missing-input-secret":
                case "invalid-input-secret":
                    logger.errorf("[reCAPTCHA] Configuration error — error-code: '%s'. "
                            + "Check the reCAPTCHA secret key in the Keycloak Admin Console.", code);
                    break;
                case "timeout-or-duplicate":
                    logger.warnf("[reCAPTCHA] Token rejected — error-code: '%s'. "
                            + "The token has expired or was already used; the user should retry.", code);
                    break;
                case "missing-input-response":
                case "invalid-input-response":
                    logger.warnf("[reCAPTCHA] Token invalid — error-code: '%s'. "
                            + "The user's reCAPTCHA response was missing or malformed.", code);
                    break;
                case "bad-request":
                    logger.errorf("[reCAPTCHA] Bad request — error-code: '%s'. "
                            + "The siteverify request was malformed; check plugin code.", code);
                    break;
                default:
                    logger.warnf("[reCAPTCHA] Verification failed — unrecognised error-code: '%s'. "
                            + "Google may have introduced a new error code.", code);
            }
        }
    }

    /**
     * Extracts values from Google's {@code error-codes} JSON array.
     * Returns an empty list when the field is absent or the array is empty.
     *
     * <p>Example input: {@code {"success":false,"error-codes":["invalid-input-response"]}}</p>
     */
    static List<String> extractErrorCodes(String json) {
        if (json == null) return Collections.emptyList();
        String normalized = json.replaceAll("\\s", "");

        int keyIndex = normalized.indexOf("\"error-codes\":[");
        if (keyIndex < 0) return Collections.emptyList();

        int arrayStart = normalized.indexOf('[', keyIndex);
        int arrayEnd   = normalized.indexOf(']', arrayStart);
        if (arrayStart < 0 || arrayEnd <= arrayStart) return Collections.emptyList();

        String arrayContent = normalized.substring(arrayStart + 1, arrayEnd);
        if (arrayContent.isEmpty()) return Collections.emptyList();

        List<String> codes = new ArrayList<>();
        for (String part : arrayContent.split(",")) {
            String code = part.replaceAll("^\"|\"$", "").trim();
            if (!code.isEmpty()) {
                codes.add(code);
            }
        }
        return codes;
    }
}
