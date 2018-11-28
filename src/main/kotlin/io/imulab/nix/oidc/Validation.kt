package io.imulab.nix.oidc

import io.imulab.nix.oauth.*

/**
 * An extension to [OAuthClientAuthenticationMethodValidator]. In OIDC spec, we have a few additional methods. Now,
 * the universe is `{client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt, none}`.
 */
object OidcClientAuthenticationMethodValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return try {
            OAuthClientAuthenticationMethodValidator.validate(value)
        } catch (e: OAuthException) {
            if (e.error == ServerError.code) {
                when (value) {
                    AuthenticationMethod.clientSecretJwt,
                    AuthenticationMethod.privateKeyJwt,
                    AuthenticationMethod.none -> value
                    else -> throw ServerError.internal("Illegal client authentication method named <$value>.")
                }
            } else {
                throw e
            }
        }
    }
}

/**
 * Validates parameter `response_mode`. The universe is `{query, fragment}`.
 * Because this parameter is optional, when used in the request, empty string is also allowed.
 */
object ResponseModeValidator : ReservedWordValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        return when (value) {
            ResponseMode.query, ResponseMode.fragment -> value
            else -> throw InvalidRequest.invalid(OidcParam.responseMode)
        }
    }

    override fun validate(request: OAuthRequest) {
        val rm = request.assertType<OidcAuthorizeRequest>().responseMode
        if (rm.isNotEmpty())
            validate(rm)
    }
}

/**
 * Validates the `nonce` parameter. Its length must not be less than [entropy]. Because this parameter is optional,
 * empty string is also allowed.
 */
class NonceValidator(private val oidcContext: OidcContext): OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val l = request.assertType<OidcAuthorizeRequest>().nonce.length
        if (l in 1..(oidcContext.nonceEntropy - 1))
            throw InvalidRequest.unmet("<nonce> length must not be less than ${oidcContext.nonceEntropy}")
    }
}

/**
 * Validates the `display` parameter. The universe if `{page, popup, touch, wap}`. Because this parameter is optional,
 * when used in a request, empty string is also allowed.
 */
object DisplayValidator : ReservedWordValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        return when(value) {
            Display.page, Display.popup, Display.touch, Display.wap -> value
            else -> throw InvalidRequest.invalid(OidcParam.display)
        }
    }

    override fun validate(request: OAuthRequest) {
        val d = request.assertType<OidcAuthorizeRequest>().display
        if (d.isNotEmpty())
            validate(d)
    }
}

/**
 * Validates the `prompt` parameter. The universe is `{none, login, consent, select_account}`. Because this parameter
 * is optional, empty set is allowed. However, `none` prompt must not be accompanied with other prompts.
 */
object PromptValidator : ReservedWordValidator, OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val prompts = request.assertType<OidcAuthorizeRequest>().prompts
        prompts.forEach { p -> validate(p) }
        if (prompts.contains(Prompt.none) && prompts.size > 1)
            throw InvalidRequest.unmet("prompt <none> must not appear along with other prompts")
    }

    override fun validate(value: String): String {
        return when(value) {
            Prompt.none, Prompt.login, Prompt.consent, Prompt.selectAccount -> value
            else -> throw InvalidRequest.invalid(OidcParam.prompt)
        }
    }
}

/**
 * Validates the `max_age` parameter. It must not be less than 0.
 */
object MaxAgeValidator : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        if (request.assertType<OidcAuthorizeRequest>().maxAge < 0)
            throw InvalidRequest.invalid(OidcParam.maxAge)
    }
}