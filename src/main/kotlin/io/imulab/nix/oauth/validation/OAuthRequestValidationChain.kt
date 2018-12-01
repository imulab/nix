package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.request.OAuthRequest

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