package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.UnauthorizedClient
import io.imulab.nix.oauth.error.UnsupportedGrantType
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.reserved.GrantType

/**
 * Validates `grant_type = {authorization_code, implicit, password, client_credentials, refresh_token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OAuthGrantTypeValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
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