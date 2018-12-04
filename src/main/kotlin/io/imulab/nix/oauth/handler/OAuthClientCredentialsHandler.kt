package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.handler.helper.RefreshTokenHelper
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.reserved.ClientType
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.StandardScope
import io.imulab.nix.oauth.response.TokenEndpointResponse

class OAuthClientCredentialsHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val refreshTokenHelper: RefreshTokenHelper
) : AccessRequestHandler {

    override suspend fun updateSession(request: OAuthAccessRequest) {
        if (!request.grantTypes.exactly(GrantType.clientCredentials))
            return

        if (request.client.type == ClientType.public)
            throw InvalidClient.authenticationRequired()

        request.scopes.forEach { request.grantScope(it) }
    }

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.grantTypes.exactly(GrantType.clientCredentials))
            return

        val accessTokenCreation = accessTokenHelper.createAccessToken(request, response)

        val refreshTokenCreation = if (request.session.grantedScopes.contains(StandardScope.offlineAccess)) {
            refreshTokenHelper.createRefreshToken(request, response)
        } else null

        response.scope = request.session.grantedScopes.toSet()

        accessTokenCreation.join()
        refreshTokenCreation?.join()
    }
}