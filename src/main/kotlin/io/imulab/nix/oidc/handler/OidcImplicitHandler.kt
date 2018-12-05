package io.imulab.nix.oidc.handler

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.handler.helper.TokenHashHelper
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.ResponseType
import io.imulab.nix.oidc.reserved.StandardScope
import io.imulab.nix.oidc.response.OidcAuthorizeEndpointResponse
import io.imulab.nix.oidc.token.IdTokenStrategy

class OidcImplicitHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val idTokenStrategy: IdTokenStrategy
) : AuthorizeRequestHandler {

    override suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse) {
        if (!request.shouldBeHandled())
            return

        check(response is OidcAuthorizeEndpointResponse) {
            "Caller should have supplied an OidcAuthorizeEndpointResponse"
        }

        request.client.mustGrantType(GrantType.implicit)

        if (request.state.isNotEmpty())
            response.state = request.state

        if (request.responseTypes.contains(io.imulab.nix.oauth.reserved.ResponseType.token)) {
            accessTokenHelper.createAccessToken(request, response).join()
            request.session.assertType<OidcSession>().idTokenClaims[IdTokenClaim.accessTokenHash] =
                    TokenHashHelper.leftMostHash(
                        response.accessToken,
                        request.client.assertType<OidcClient>().idTokenSignedResponseAlgorithm
                    )
            response.handledResponseTypes.add(io.imulab.nix.oauth.reserved.ResponseType.token)
        }

        response.idToken = idTokenStrategy.generateToken(request)
        response.handledResponseTypes.add(ResponseType.idToken)
    }

    private fun OAuthAuthorizeRequest.shouldBeHandled(): Boolean {
        if (!session.grantedScopes.contains(StandardScope.openid))
            return false
        else if (session !is OidcSession)
            return false

        return when {
            responseTypes.exactly(ResponseType.idToken) -> true
            responseTypes.containsAll(
                listOf(
                    ResponseType.idToken,
                    io.imulab.nix.oauth.reserved.ResponseType.token
                )
            ) -> true
            else -> false
        }
    }
}