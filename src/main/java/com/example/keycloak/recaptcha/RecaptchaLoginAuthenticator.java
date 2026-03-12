package com.example.keycloak.recaptcha;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;

/**
 * Keycloak reCAPTCHA Login Authenticator
 *
 * <p>Extends the built-in {@link UsernamePasswordForm} to inject Google reCAPTCHA v2
 * validation into the browser login flow. The reCAPTCHA token is verified against
 * Google's siteverify API before credentials are checked, blocking bot-driven
 * brute-force attacks at the earliest possible point.</p>
 *
 * <p>All network communication is delegated to {@link RecaptchaVerificationService},
 * which is injected at construction time by {@link RecaptchaLoginAuthenticatorFactory}.
 * This makes the authenticator independently unit-testable by supplying a mock service.</p>
 *
 * <p><b>Deployment:</b> Copy the plugin JAR to {@code $KEYCLOAK_HOME/providers/},
 * then run {@code bin/kc.sh build}. See README.md for full setup instructions.</p>
 */
public class RecaptchaLoginAuthenticator extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(RecaptchaLoginAuthenticator.class);

    /** Google's reCAPTCHA token form field name (injected by the JS widget). */
    static final String RECAPTCHA_RESPONSE_FIELD = "g-recaptcha-response";

    private final RecaptchaVerificationService verificationService;

    /**
     * @param verificationService the service that calls Google's siteverify API;
     *                            must not be {@code null}
     */
    RecaptchaLoginAuthenticator(RecaptchaVerificationService verificationService) {
        this.verificationService = verificationService;
    }

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
            // UNAUTHORIZED_ACCESS rather than INTERNAL_ERROR: a missing secret key means the
            // reCAPTCHA check cannot be performed at all, so the login must be denied outright.
            // INTERNAL_ERROR would still block login, but its semantics imply a server fault
            // rather than an explicit security gate, and some flow configurations treat it
            // differently (e.g. retry logic). UNAUTHORIZED_ACCESS makes the intent unambiguous.
            logger.error("[reCAPTCHA] Secret key is not configured — denying login. "
                    + "Configure the reCAPTCHA secret key in the Keycloak Admin Console.");
            context.failure(AuthenticationFlowError.UNAUTHORIZED_ACCESS);
            return;
        }

        String remoteAddr = context.getConnection().getRemoteAddr();
        boolean verified = verificationService.verify(recaptchaToken, secretKey, remoteAddr);
        if (!verified) {
            logger.warn("[reCAPTCHA] Token verification failed — rejecting login attempt");
            renderChallengeWithError(context, siteKey, "recaptchaFailed");
            return;
        }

        logger.debug("[reCAPTCHA] Token verified successfully — proceeding to credential check");
        super.action(context);
    }

    // -----------------------------------------------------------------------
    // Form helpers
    // -----------------------------------------------------------------------

    private LoginFormsProvider buildLoginForm(AuthenticationFlowContext context, String siteKey) {
        return context.form()
                .setAttribute("recaptchaRequired", true)
                .setAttribute("recaptchaSiteKey", siteKey);
    }

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
