package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.request.OidcAuthorizeRequest

/**
 * Validates the `nonce` parameter. Its length must not be less than [entropy]. Because this parameter is optional,
 * empty string is also allowed.
 */
class NonceValidator(private val oidcContext: OidcContext):
    OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val l = request.assertType<OidcAuthorizeRequest>().nonce.length
        if (l in 1..(oidcContext.nonceEntropy - 1))
            throw InvalidRequest.unmet("<nonce> length must not be less than ${oidcContext.nonceEntropy}")
    }
}