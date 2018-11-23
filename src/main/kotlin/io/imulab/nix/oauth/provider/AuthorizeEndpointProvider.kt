package io.imulab.nix.oauth.provider

import io.imulab.nix.client.manager.ClientStore
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeResponse
import io.imulab.nix.oauth.session.OAuthSession
import io.imulab.nix.oauth.vor.JsonWebKeySetVor
import io.imulab.nix.oauth.vor.OidcRequestObjectVor
import io.ktor.application.ApplicationCall
import kotlinx.coroutines.CoroutineScope
import org.jose4j.jwk.JsonWebKeySet

interface AuthorizeEndpointProvider {

    val requestScope: CoroutineScope
    val clientStore: ClientStore
    val stateEntropy: Int
    val oidcRequestObjectAudience: String
    val oidcRequestObjectVor: OidcRequestObjectVor
    val jsonWebKeySetVor: JsonWebKeySetVor
    val jwxProvider: JwxProvider
    val serverJsonWebKeySet: JsonWebKeySet

    suspend fun newAuthorizeRequest(call: ApplicationCall): AuthorizeRequest

    suspend fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse

    suspend fun writeAuthorizeResponse(call: ApplicationCall, request: AuthorizeRequest, response: AuthorizeResponse)

    suspend fun writeAuthorizeError(call: ApplicationCall, request: AuthorizeRequest?, error: Throwable)
}