package io.imulab.nix.oidc.handler

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.handler.AccessRequestHandler
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.handler.helper.TokenHashHelper
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.StandardScope
import io.imulab.nix.oidc.response.OidcTokenEndpointResponse
import io.imulab.nix.oidc.token.IdTokenStrategy

class OidcRefreshHandler(private val idTokenStrategy: IdTokenStrategy) : AccessRequestHandler {

    override suspend fun updateSession(request: OAuthAccessRequest) {}

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.shouldBeHandled())
            return

        check(response is OidcTokenEndpointResponse) {
            "Upstream should have supplied an OidcTokenEndpointResponse"
        }

        check(response.accessToken.isNotEmpty()) {
            "Upstream should have generated an access token. Was handler misplaced?"
        }

        request.session.assertType<OidcSession>().idTokenClaims[IdTokenClaim.accessTokenHash] =
                TokenHashHelper.leftMostHash(
                    response.accessToken,
                    request.client.assertType<OidcClient>().idTokenSignedResponseAlgorithm
                )
        response.idToken = idTokenStrategy.generateToken(request)
    }

    private fun OAuthAccessRequest.shouldBeHandled(): Boolean =
        grantTypes.contains(GrantType.refreshToken) && session.grantedScopes.contains(StandardScope.openid)
}