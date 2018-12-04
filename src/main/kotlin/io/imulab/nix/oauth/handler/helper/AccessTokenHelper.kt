package io.imulab.nix.oauth.handler.helper

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.strategy.AccessTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AccessTokenHelper(
    private val oauthContext: OAuthContext,
    private val accessTokenStrategy: AccessTokenStrategy,
    private val accessTokenRepository: AccessTokenRepository
) {

    suspend fun createAccessToken(request: OAuthAccessRequest, response: TokenEndpointResponse): Job {
        return accessTokenStrategy.generateToken(request).let { accessToken ->
            response.accessToken = accessToken
            response.tokenType = "bearer"
            response.expiresIn = oauthContext.accessTokenLifespan.toSeconds()
            withContext(Dispatchers.IO) {
                launch {
                    accessTokenRepository.createAccessTokenSession(accessToken, request)
                }
            }
        }
    }
}