package com.example.keycloak.recaptcha;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * Factory that registers {@link RecaptchaLoginAuthenticator} with Keycloak's SPI framework.
 *
 * <p>This factory appears in the Admin Console under Authentication → Flows → Add Step,
 * labelled "Username Password Form with reCAPTCHA". Two config fields are exposed:
 * <ul>
 *   <li>{@code recaptcha.site.key}  — your Google reCAPTCHA v2 site key (public)</li>
 *   <li>{@code recaptcha.secret.key} — your Google reCAPTCHA v2 secret key (private)</li>
 * </ul>
 */
public class RecaptchaLoginAuthenticatorFactory implements AuthenticatorFactory {

    /** Unique provider ID — used internally by Keycloak to identify this authenticator. */
    public static final String PROVIDER_ID = "recaptcha-login-authenticator";

    /** Config property keys (used in authenticator config in the Admin Console). */
    public static final String CONFIG_SITE_KEY   = "recaptcha.site.key";
    public static final String CONFIG_SECRET_KEY = "recaptcha.secret.key";

    /** Singleton instance — Authenticators are stateless and safe to share. */
    private static final RecaptchaLoginAuthenticator SINGLETON = new RecaptchaLoginAuthenticator();

    // -----------------------------------------------------------------------
    // ProviderFactory / AuthenticatorFactory implementation
    // -----------------------------------------------------------------------

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Username Password Form with reCAPTCHA";
    }

    @Override
    public String getReferenceCategory() {
        return "recaptcha";
    }

    @Override
    public String getHelpText() {
        return "Validates Google reCAPTCHA v2 before checking username and password. "
             + "Use this as a drop-in replacement for the standard 'Username Password Form' "
             + "execution in your browser authentication flow.";
    }

    /**
     * Configuration properties shown in the Keycloak Admin Console when
     * this execution is added to a flow.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty siteKey = new ProviderConfigProperty();
        siteKey.setName(CONFIG_SITE_KEY);
        siteKey.setLabel("reCAPTCHA Site Key");
        siteKey.setType(ProviderConfigProperty.STRING_TYPE);
        siteKey.setHelpText("The public site key obtained from https://www.google.com/recaptcha/admin. "
                          + "Used to render the reCAPTCHA widget on the login page.");
        siteKey.setRequired(true);

        ProviderConfigProperty secretKey = new ProviderConfigProperty();
        secretKey.setName(CONFIG_SECRET_KEY);
        secretKey.setLabel("reCAPTCHA Secret Key");
        secretKey.setType(ProviderConfigProperty.PASSWORD);
        secretKey.setHelpText("The private secret key obtained from https://www.google.com/recaptcha/admin. "
                            + "Used to verify the reCAPTCHA token with Google's API. Keep this confidential.");
        secretKey.setRequired(true);
        secretKey.setSecret(true);

        return Arrays.asList(siteKey, secretKey);
    }

    // -----------------------------------------------------------------------
    // Authenticator creation
    // -----------------------------------------------------------------------

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // No static config needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-init needed
    }

    @Override
    public void close() {
        // Nothing to clean up
    }

    // -----------------------------------------------------------------------
    // Flow requirements
    // -----------------------------------------------------------------------

    /**
     * Defines the valid requirement options for this execution in a flow.
     * REQUIRED and DISABLED cover the common use-cases; ALTERNATIVE is included
     * in case admins want to make reCAPTCHA optional alongside another authenticator.
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        // Users do not need to "set up" reCAPTCHA — it is always required
        return false;
    }

    @Override
    public boolean isConfigurable() {
        // Config (site key / secret key) is entered via the Admin Console
        return true;
    }
}
