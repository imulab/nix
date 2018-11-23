package io.imulab.nix.oauth.provider.authorize

import io.imulab.nix.client.manager.ClientStore
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.oauth.provider.AuthorizeEndpointProvider
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeResponse
import io.imulab.nix.oauth.session.OAuthSession
import io.imulab.nix.oauth.vor.JsonWebKeySetVor
import io.imulab.nix.oauth.vor.OidcRequestObjectVor
import io.ktor.application.ApplicationCall
import kotlinx.coroutines.CoroutineScope
import org.jose4j.jwk.JsonWebKeySet

class NixAuthorizeProvider(
    override val requestScope: CoroutineScope,
    override val clientStore: ClientStore,
    override val stateEntropy: Int = 8,
    override val oidcRequestObjectAudience: String,
    override val oidcRequestObjectVor: OidcRequestObjectVor,
    override val jsonWebKeySetVor: JsonWebKeySetVor,
    override val jwxProvider: JwxProvider,
    override val serverJsonWebKeySet: JsonWebKeySet
) : AuthorizeEndpointProvider {

    override suspend fun newAuthorizeRequest(call: ApplicationCall): AuthorizeRequest {
        return doHandleAuthorizeRequest(call)
    }

    override suspend fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override suspend fun writeAuthorizeResponse(
        call: ApplicationCall,
        request: AuthorizeRequest,
        response: AuthorizeResponse
    ) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override suspend fun writeAuthorizeError(call: ApplicationCall, request: AuthorizeRequest?, error: Throwable) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}