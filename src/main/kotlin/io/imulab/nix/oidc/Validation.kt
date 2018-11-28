package io.imulab.nix.oidc

import io.imulab.nix.oauth.*
import java.time.LocalDateTime

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

/**
 * Validates the relation between `max_age`, `auth_time` and `prompt`. This validator assumes all previous
 * authorization request has been revived and authentication information has also been merged into request
 * session. Hence, it is recommended to place this validator behind the aforementioned actions.
 *
 * Under these assumptions, this validator enforces the following rules:
 * - `auth_time` is optional when `max_age` is not specified, or it has not been requested as an essential claim.
 * - `auth_time`, if present, must not be in the future
 * - `auth_time` and `max_age`, if present, must form such relation that `auth_time + max_age >= now`.
 * - when `prompt` is set to `login`, `auth_time` must happen after the original (before redirection) request time.
 * - when `prompt` is set to `none`, `auth_time` must happen before the current request time.
 */
object AuthTimeValidator : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OidcAuthorizeRequest>()
        val session = ar.session.assertType<OidcSession>()
        val authTime = session.authTime

        if (authTime == null) {
            when {
                ar.maxAge > 0 ->
                    throw ServerError.internal("<auth_time> must be specified when <max_age> is specified.")
                ar.claims.hasEssentialClaim(IdTokenClaim.authTime) ->
                    throw ServerError.internal("<auth_time> must be specified when it is requested as an essential claim.")
            }
            return
        }

        if (authTime.isAfter(LocalDateTime.now()))
            throw AccessDenied.byServer("Untrusted authentication (happened in the future).")

        if (ar.maxAge > 0) {
            if (authTime.plusSeconds(ar.maxAge).isBefore(LocalDateTime.now()))
                throw AccessDenied.byServer("Authentication expired (<auth_time> happened longer ago than <max_age>).")
        }

        if (ar.prompts.contains(Prompt.login)) {
            if (authTime.isBefore(session.originalRequestTime ?: ar.requestTime))
                throw AccessDenied.byServer("Authentication did not happen (<login> prompt requested but <auth_time> is still before original request time).")
        }

        if (ar.prompts.contains(Prompt.none)) {
            if (authTime.isAfter(ar.requestTime))
                throw AccessDenied.byServer("New authentication took place (<none> prompt requested by <auth_time> is after request time).")
        }
    }
}