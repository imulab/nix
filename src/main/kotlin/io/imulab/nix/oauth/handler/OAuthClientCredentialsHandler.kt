package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.reserved.ClientType
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.StandardScope
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.storage.RefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.AccessTokenStrategy
import io.imulab.nix.oauth.token.strategy.RefreshTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OAuthClientCredentialsHandler(
    private val oauthContext: OAuthContext,
    private val accessTokenStrategy: AccessTokenStrategy,
    private val accessTokenRepository: AccessTokenRepository,
    private val refreshTokenStrategy: RefreshTokenStrategy,
    private val refreshTokenRepository: RefreshTokenRepository
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

        val accessTokenCreation = accessTokenStrategy.generateToken(request).let { accessToken ->
            response.accessToken = accessToken
            response.tokenType = "bearer"
            response.expiresIn = oauthContext.accessTokenLifespan.toSeconds()
            withContext(Dispatchers.IO) {
                launch {
                    accessTokenRepository.createAccessTokenSession(accessToken, request)
                }
            }
        }

        val refreshTokenCreation = if (request.session.grantedScopes.contains(StandardScope.offlineAccess)) {
            refreshTokenStrategy.generateToken(request).let { refreshToken ->
                response.refreshToken = refreshToken
                withContext(Dispatchers.IO) {
                    launch {
                        refreshTokenRepository.createRefreshTokenSession(refreshToken, request)
                    }
                }
            }
        } else null

        response.scope = request.session.grantedScopes.toSet()

        accessTokenCreation.join()
        refreshTokenCreation?.join()
    }
}