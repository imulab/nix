package io.imulab.nix.oidc.response

import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oidc.reserved.OidcParam

class OidcAuthorizeEndpointResponse(
    override var idToken: String = ""
) : AuthorizeEndpointResponse(), IdTokenResponse {

    override val data: Map<String, String>
        get() {
            val m = super.data as MutableMap
            if (idToken.isNotEmpty())
                m[OidcParam.idToken] = idToken
            return m
        }
}