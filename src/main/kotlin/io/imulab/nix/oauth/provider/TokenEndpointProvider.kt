package io.imulab.nix.oauth.provider

import io.imulab.nix.oauth.request.TokenRequest
import io.imulab.nix.oauth.response.TokenResponse
import io.imulab.nix.oauth.session.OAuthSession
import io.ktor.application.ApplicationCall

interface TokenEndpointProvider {

    suspend fun newTokenRequest(call: ApplicationCall, session: OAuthSession): TokenRequest

    suspend fun newTokenResponse(request: TokenRequest): TokenResponse

    suspend fun writeTokenResponse(call: ApplicationCall, request: TokenRequest, response: TokenResponse)

    suspend fun writeTokenError(call: ApplicationCall, request: TokenRequest?, error: Throwable)
}