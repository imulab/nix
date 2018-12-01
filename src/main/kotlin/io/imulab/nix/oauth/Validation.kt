package io.imulab.nix.oauth

import io.imulab.nix.oauth.reserved.*
import java.net.URI

/**
 * Rule to validate an [OAuthRequest]. Implementation should raise an error when validation fails; otherwise, should
 * return normally.
 */
interface OAuthRequestValidation {
    fun validate(request: OAuthRequest)
}

/**
 * Validation container which delegates work to [validators] one by one.
 */
class OAuthRequestValidationChain(
    private val validators: List<OAuthRequestValidation>
) : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        validators.forEach { it.validate(request) }
    }
}

/**
 * Validates the parameter `redirectUri`. First, it must be pre-registered with the client. Second, if http
 * scheme is used, the host must be _localhost_ or _127.0.0.1_.
 */
object RedirectUriValidator : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OAuthAuthorizeRequest>()
        if (ar.redirectUri.isEmpty())
            throw InvalidRequest.required(Param.redirectUri)

        if (!ar.client.redirectUris.contains(ar.redirectUri))
            throw InvalidRequest.invalid(Param.redirectUri)

        URI(ar.redirectUri).let { uri ->
            if (uri.scheme.toLowerCase() == "http")
                when (uri.host.toLowerCase()) {
                    "localhost", "127.0.0.1" -> {}
                    else -> throw InvalidRequest.invalid(Param.redirectUri)
                }
            if (uri.rawFragment != null && uri.rawFragment.isNotEmpty())
                throw InvalidRequest.invalid(Param.redirectUri)
        }
    }
}

/**
 * Validate the parameter `state`. Its entropy must not be less than [OAuthContext.stateEntropy]. Because this is an
 * optional parameter, empty string is allowed.
 */
class StateValidator(private val oauthContext: OAuthContext) : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val l = request.assertType<OAuthAuthorizeRequest>().state.length
        if (l in 1..(oauthContext.stateEntropy - 1))
            throw InvalidRequest.unmet("<state> length must not be less than ${oauthContext.stateEntropy}")
    }
}

/**
 * Validate the parameter `scope`. It must not be malformed according to OAuth spec and
 * it must be allowed by the requesting client.
 */
object ScopeValidator : SpecDefinitionValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        value.mustNotMalformedScope()
        return value
    }

    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OAuthAuthorizeRequest>()
        ar.scopes.forEach { scope ->
            scope.mustNotMalformedScope()
            ar.client.mustScope(scope)
        }
    }
}

/**
 * Interface to validate a value conforms to specification definition.
 *
 * This validator replaces the function which would otherwise be enforced by the use of Enum classes. However, because
 * we require extensibility by design, Enum classes cannot be used for this purpose. As a result, we have to defer to
 * the use of plain data types (such as, in this case, string) and require interfaces like this to validate values
 * manually.
 */
interface SpecDefinitionValidator {
    fun validate(value: String): String
}

/**
 * Validates the set relation: `response_type = {code, token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OAuthResponseTypeValidator : SpecDefinitionValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        return when (value) {
            ResponseType.code, ResponseType.token -> value
            else -> throw UnsupportedResponseType.unsupported(value)
        }
    }

    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OAuthAuthorizeRequest>()
        ar.responseTypes.forEach {
            validate(it)
            if (!ar.client.responseTypes.contains(it))
                throw UnauthorizedClient.forbiddenResponseType(it)
        }
    }
}

/**
 * Validates `grant_type = {authorization_code, implicit, password, client_credentials, refresh_token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OAuthGrantTypeValidator : SpecDefinitionValidator, OAuthRequestValidation {
    override fun validate(value: String): String {
        return when (value) {
            GrantType.authorizationCode,
            GrantType.implicit,
            GrantType.password,
            GrantType.clientCredentials,
            GrantType.refreshToken -> value
            else -> throw UnsupportedGrantType.unsupported(value)
        }
    }

    override fun validate(request: OAuthRequest) {
        val ac = request.assertType<OAuthAccessRequest>()
        ac.grantTypes.forEach {
            validate(it)
            if (!ac.client.grantTypes.contains(it))
                throw UnauthorizedClient.forbiddenGrantType(it)
        }
    }
}

/**
 * Validates `client_type = {public, confidential}`.
 */
object ClientTypeValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when (value) {
            ClientType.public, ClientType.confidential -> value
            else -> throw ServerError.internal("Illegal client type <$value>.")
        }
    }
}

/**
 * Validates client authentication method is one of `{client_secret_basic, client_secret_post}`.
 */
object OAuthClientAuthenticationMethodValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when (value) {
            AuthenticationMethod.clientSecretBasic,
            AuthenticationMethod.clientSecretPost -> value
            else -> throw ServerError.internal("Illegal client authentication method named <$value>.")
        }
    }
}