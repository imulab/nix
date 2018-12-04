package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.storage.RefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.AccessTokenStrategy
import io.imulab.nix.oauth.token.strategy.RefreshTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OAuthRefreshHandler(
    private val oauthContext: OAuthContext,
    private val accessTokenStrategy: AccessTokenStrategy,
    private val accessTokenRepository: AccessTokenRepository,
    private val refreshTokenStrategy: RefreshTokenStrategy,
    private val refreshTokenRepository: RefreshTokenRepository
) : AccessRequestHandler {

    override suspend fun updateSession(request: OAuthAccessRequest) {
        if (!request.grantTypes.exactly(GrantType.refreshToken))
            return

        val originalRequest = request.refreshToken
            .also { refreshTokenStrategy.verifyToken(it, request) }
            .let { refreshTokenRepository.getRefreshTokenSession(it) }

        request.session.merge(originalRequest.session)
        request.session.originalRequestId = originalRequest.id
    }

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.grantTypes.exactly(GrantType.refreshToken))
            return

        val refreshTokenRemoval = withContext(Dispatchers.IO) {
            launch {
                refreshTokenRepository.deleteRefreshTokenAssociatedWithRequest(request.session.originalRequestId)
            }
        }
        val accessTokenRemoval = withContext(Dispatchers.IO) {
            launch {
                accessTokenRepository.deleteAccessTokenAssociatedWithRequest(request.session.originalRequestId)
            }
        }

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

        val refreshTokenCreation = refreshTokenStrategy.generateToken(request).let { refreshToken ->
            response.refreshToken = refreshToken
            withContext(Dispatchers.IO) {
                launch {
                    refreshTokenRepository.createRefreshTokenSession(refreshToken, request)
                }
            }
        }

        response.scope = request.session.grantedScopes.toSet()

        refreshTokenRemoval.join()
        accessTokenRemoval.join()
        accessTokenCreation.join()
        refreshTokenCreation.join()
    }
}