package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.UnauthorizedClient
import io.imulab.nix.oauth.error.UnsupportedResponseType
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.reserved.ResponseType

/**
 * Validates the set relation: `response_type = {code, token}`.
 * When in the context of a request, it must be registered/allowed by the client.
 */
object OAuthResponseTypeValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
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