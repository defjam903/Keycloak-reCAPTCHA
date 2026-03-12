<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <#if realm.password>
                    <form id="kc-form-login" onsubmit="return validateRecaptchaAndSubmit();"
                          action="${url.loginAction}" method="post">

                        <#-- ── Username field ── -->
                        <div class="${properties.kcFormGroupClass!}">
                            <label for="username" class="${properties.kcLabelClass!}">
                                <#if !realm.loginWithEmailAllowed>
                                    ${msg("username")}
                                <#elseif !realm.registrationEmailAsUsername>
                                    ${msg("usernameOrEmail")}
                                <#else>
                                    ${msg("email")}
                                </#if>
                            </label>
                            <input tabindex="1" id="username"
                                   class="${properties.kcInputClass!}"
                                   name="username"
                                   value="${(login.username!'')?html}"
                                   type="text"
                                   autofocus
                                   autocomplete="off"
                                   aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                            />
                            <#if messagesPerField.existsError('username','password')>
                                <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                    ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                                </span>
                            </#if>
                        </div>

                        <#-- ── Password field ── -->
                        <div class="${properties.kcFormGroupClass!}">
                            <label for="password" class="${properties.kcLabelClass!}">
                                ${msg("password")}
                            </label>
                            <div class="${properties.kcInputGroup!}">
                                <input tabindex="2" id="password"
                                       class="${properties.kcInputClass!}"
                                       name="password"
                                       type="password"
                                       autocomplete="current-password"
                                       aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                                />
                                <button class="${properties.kcFormPasswordVisibilityButtonClass!}"
                                        type="button"
                                        aria-label="${msg('showPassword')}"
                                        aria-controls="password"
                                        data-password-toggle
                                        data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}"
                                        data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                        data-label-show="${msg('showPassword')}"
                                        data-label-hide="${msg('hidePassword')}">
                                    <i class="${properties.kcFormPasswordVisibilityIconShow!}"
                                       aria-hidden="true"></i>
                                </button>
                            </div>
                        </div>

                        <#-- ── Remember me + Forgot password ── -->
                        <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                            <div id="kc-form-options">
                                <#if realm.rememberMe && !usernameEditDisabled??>
                                    <div class="checkbox">
                                        <label>
                                            <#if login.rememberMe??>
                                                <input tabindex="3" id="rememberMe" name="rememberMe"
                                                       type="checkbox" checked> ${msg("rememberMe")}
                                            <#else>
                                                <input tabindex="3" id="rememberMe" name="rememberMe"
                                                       type="checkbox"> ${msg("rememberMe")}
                                            </#if>
                                        </label>
                                    </div>
                                </#if>
                            </div>
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                                <#if realm.resetPasswordAllowed>
                                    <span>
                                        <a tabindex="5"
                                           href="${url.loginResetCredentialsUrl}">
                                            ${msg("doForgotPassword")}
                                        </a>
                                    </span>
                                </#if>
                            </div>
                        </div>

                        <#-- ── reCAPTCHA v2 widget ── -->
                        <#if recaptchaRequired??>
                            <div class="${properties.kcFormGroupClass!}">
                                <div id="kc-recaptcha-wrapper" style="margin: 12px 0;">
                                    <div class="g-recaptcha"
                                         data-sitekey="${recaptchaSiteKey}"
                                         data-callback="onRecaptchaSuccess"
                                         data-expired-callback="onRecaptchaExpired">
                                    </div>
                                    <#-- Hidden error shown when user submits without completing reCAPTCHA -->
                                    <span id="recaptcha-error"
                                          style="display:none; color:#d93025; font-size:0.85em; margin-top:4px;">
                                        ${msg("recaptchaRequired")}
                                    </span>
                                </div>
                            </div>
                        </#if>

                        <#-- ── Submit button ── -->
                        <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                            <input type="hidden" id="id-hidden-input" name="credentialId"
                                   <#if auth.selectedCredential?has_content>
                                       value="${auth.selectedCredential}"
                                   </#if>
                            />
                            <input tabindex="4"
                                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                   name="login"
                                   id="kc-login"
                                   type="submit"
                                   value="${msg("doLogIn")}"/>
                        </div>
                    </form>
                </#if>
            </div>
        </div>

        <#-- ── Google reCAPTCHA JS + validation ── -->
        <#if recaptchaRequired??>
            <script src="https://www.google.com/recaptcha/api.js" async defer></script>
            <script>
                var recaptchaCompleted = false;

                function onRecaptchaSuccess(token) {
                    recaptchaCompleted = true;
                    document.getElementById('recaptcha-error').style.display = 'none';
                }

                function onRecaptchaExpired() {
                    recaptchaCompleted = false;
                    grecaptcha.reset();
                }

                /**
                 * Client-side guard: prevents form submission if reCAPTCHA
                 * has not been completed.  The server always re-validates the
                 * token regardless of this check.
                 */
                function validateRecaptchaAndSubmit() {
                    var token = document.querySelector('.g-recaptcha-response');
                    if (!token || !token.value) {
                        document.getElementById('recaptcha-error').style.display = 'block';
                        return false;
                    }
                    return true;
                }
            </script>
        </#if>

    <#elseif section = "info">
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container">
                <div id="kc-registration">
                    <span>
                        ${msg("noAccount")}
                        <a tabindex="6" href="${url.registrationUrl}">
                            ${msg("doRegister")}
                        </a>
                    </span>
                </div>
            </div>
        </#if>
    <#elseif section = "socialProviders">
        <#if realm.password && social.providers??>
            <div id="kc-social-providers" class="${properties.kcFormSocialAccountSectionClass!}">
                <hr/>
                <h2>${msg("identity-provider-login-label")}</h2>
                <ul class="${properties.kcFormSocialAccountListClass!}
                    <#if social.providers?size gt 3>
                        ${properties.kcFormSocialAccountListGridClass!}
                    </#if>">
                    <#list social.providers as p>
                        <li>
                            <a id="social-${p.alias}"
                               class="${properties.kcFormSocialAccountListButtonClass!}
                                   <#if social.providers?size gt 3>
                                       ${properties.kcFormSocialAccountGridItem!}
                                   </#if>"
                               type="button"
                               href="${p.loginUrl}">
                                <#if p.iconClasses?has_content>
                                    <i class="${properties.kcCommonLogoIdP!} ${p.iconClasses!}"
                                       aria-hidden="true"></i>
                                    <span class="${properties.kcFormSocialAccountNameClass!}
                                        <#if social.providers?size gt 3>
                                            ${properties.kcFormSocialAccountGridItemIconClass!}
                                        </#if>">
                                        ${p.displayName!}
                                    </span>
                                <#else>
                                    <span>${p.displayName!}</span>
                                </#if>
                            </a>
                        </li>
                    </#list>
                </ul>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
