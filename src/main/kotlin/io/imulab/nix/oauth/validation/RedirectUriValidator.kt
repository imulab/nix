package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.reserved.Param
import java.net.URI

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