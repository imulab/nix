package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.mustNotMalformedScope
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest

/**
 * Validate the parameter `scope`. It must not be malformed according to OAuthConfig spec and
 * it must be allowed by the requesting client.
 */
object ScopeValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
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