package io.imulab.nix.oidc

import io.imulab.nix.oauth.*
import io.imulab.nix.oauth.error.*
import io.imulab.nix.oidc.discovery.Discovery
import io.imulab.nix.oidc.discovery.OidcContext
import java.lang.Exception
import java.time.LocalDateTime

/**
 * An extension to [OAuthClientAuthenticationMethodValidator]. In OIDC spec, we have a few additional methods. Now,
 * the universe is `{client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt, none}`.
 */
object OidcClientAuthenticationMethodValidator : SpecDefinitionValidator {
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
 * Validates the set relation: `response_type = {code, token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OidcResponseTypeValidator : SpecDefinitionValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        try {
            return OAuthResponseTypeValidator.validate(value)
        } catch (e: Exception) {
            if (value == ResponseType.idToken)
                return value
            throw UnsupportedResponseType.unsupported(value)
        }
    }

    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OidcAuthorizeRequest>()
        ar.responseTypes.forEach {
            validate(it)
            if (!ar.client.responseTypes.contains(it))
                throw UnauthorizedClient.forbiddenResponseType(it)
        }
    }
}

/**
 * Validates parameter `response_mode`. The universe is `{query, fragment}`.
 * Because this parameter is optional, when used in the request, empty string is also allowed.
 */
object ResponseModeValidator : SpecDefinitionValidator, OAuthRequestValidation {
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
 * Validates the JWT signing algorithm. The universe is everything specified in [JwtSigningAlgorithm].
 */
object SigningAlgorithmValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        if (!JwtSigningAlgorithm.values().map { it.spec }.contains(value))
            throw IllegalArgumentException("$value is not a valid signing algorithm.")
        return value
    }
}

/**
 * Validates the JWE encryption algorithm. The universe is everything specified in [JweKeyManagementAlgorithm].
 */
object EncryptionAlgorithmValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        if (!JweKeyManagementAlgorithm.values().map { it.spec }.contains(value))
            throw IllegalArgumentException("$value is not a valid key management encryption algorithm.")
        return value
    }
}

/**
 * Validates the JWE encryption algorithm. The universe is everything specified in [JweContentEncodingAlgorithm].
 */
object EncryptionEncodingValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        if (!JweContentEncodingAlgorithm.values().map { it.spec }.contains(value))
            throw IllegalArgumentException("$value is not a valid content encoding algorithm.")
        return value
    }
}

/**
 * Validates the claim type configuration parameter. The universe is `{normal, aggregated, distributed}`.
 */
object ClaimTypeValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when (value) {
            ClaimType.normal, ClaimType.aggregated, ClaimType.distributed -> value
            else -> throw IllegalArgumentException("$value is not a valid claim type.")
        }
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
object DisplayValidator : SpecDefinitionValidator, OAuthRequestValidation {
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
 * Validates subject type values. The universe is `{public, pairwise}`.
 */
object SubjectTypeValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when(value) {
            SubjectType.public, SubjectType.pairwise -> value
            else -> throw IllegalArgumentException("$value is not a valid subject type.")
        }
    }
}

/**
 * Validates the `prompt` parameter. The universe is `{none, login, consent, select_account}`. Because this parameter
 * is optional, empty set is allowed. However, `none` prompt must not be accompanied with other prompts.
 */
object PromptValidator : SpecDefinitionValidator, OAuthRequestValidation {
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
                throw AccessDenied.authenticationExpired()
        }

        if (ar.prompts.contains(Prompt.login)) {
            if (authTime.isBefore(session.originalRequestTime ?: ar.requestTime))
                throw AccessDenied.oldAuthenticationOnLoginPrompt()
        }

        if (ar.prompts.contains(Prompt.none)) {
            if (authTime.isAfter(ar.requestTime))
                throw AccessDenied.newAuthenticationOnNonePrompt()
        }
    }
}

/**
 * Validates if the incoming parameters are actually supported by the server. Support information is supplied through
 * OIDC [Discovery] configuration.
 */
class SupportValidator(private val discovery: Discovery) : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        when (request) {
            is OidcAuthorizeRequest -> validate(request)
            is OAuthAccessRequest -> validate(request)
        }
    }

    private fun validate(request: OidcAuthorizeRequest) {
        request.responseTypes
            .find { !discovery.responseTypesSupported.contains(it) }
            .ifNotNullOrEmpty { throw UnsupportedResponseType.unsupported(it) }

        request.acrValues
            .find { !discovery.acrValuesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.acrValues) }

        request.claimsLocales
            .find { !discovery.claimsLocalesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.claimsLocales) }

        request.uiLocales
            .find { !discovery.uiLocalesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.uiLocales) }

        if (request.responseMode.isNotEmpty() && !discovery.responseModeSupported.contains(request.responseMode))
            throw RequestNotSupported.unsupported(OidcParam.responseMode)

        if (request.display.isNotEmpty() && !discovery.displayValuesSupported.contains(request.display))
            throw RequestNotSupported.unsupported(OidcParam.display)

        if (!request.claims.isEmpty() && !discovery.claimsParameterSupported)
            throw RequestNotSupported.unsupported(OidcParam.claims)
    }

    private fun validate(request: OAuthAccessRequest) {
        request.grantTypes.find { !discovery.grantTypesSupported.contains(it) }.let { unsupported ->
            if (unsupported != null)
                throw UnsupportedGrantType.unsupported(unsupported)
        }
    }
}
