package io.imulab.nix.oauth.provider

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.manager.ClientStore
import io.imulab.nix.constant.ErrorCode
import io.imulab.nix.constant.Misc
import io.imulab.nix.constant.Param
import io.imulab.nix.constant.Scope
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.request.NixAuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeResponse
import io.imulab.nix.oauth.session.OAuthSession
import io.imulab.nix.oauth.session.Session
import io.imulab.nix.oauth.vor.OidcRequestObjectVor
import io.imulab.nix.support.*
import io.ktor.application.ApplicationCall
import io.ktor.request.receiveParameters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async

class NixAuthorizeProvider(
    private val clientStore: ClientStore,
    private val clientStoreCoroutineScope: CoroutineScope,
    private val stateEntropy: Int = 8,
    private val oidcRequestObjectVor: OidcRequestObjectVor
) : AuthorizeEndpointProvider {

    override suspend fun newAuthorizeRequest(call: ApplicationCall): AuthorizeRequest {
        val form = mutableMapOf<String, String>().also {
            call.receiveParameters().forEach { s, list ->
                when (list.size) {
                    0 -> {}
                    1 -> it[s] = list[0]
                    else -> throw InvalidRequestException(
                        subCode = ErrorCode.Sub.DUPLICATE_PARAM,
                        message = "Parameters cannot be included more than once."
                    )
                }
            }
        }

        val deferredClient = clientStoreCoroutineScope.async { clientStore.getClient(form.mustClientId()) }

        return NixAuthorizeRequest.Companion.Builder()
            .also { b ->
                b.requestForm = form
                b.redirectUri = form.redirectUri()
                b.session = Session()
                b.state = form.mustStateWithEnoughEntropy(stateEntropy)
                b.addResponseType(form.mustResponseTypes())
                b.addRequestScope(form.scopes())
            }
            .also { b ->
                if (!form.scopes().contains(Scope.OPENID))
                    return@also
                oidcRequestObjectVor.resolve(
                    form.request(),
                    form.requestUri(),
                    deferredClient
                )?.claimsMap?.forEach { k, v ->
                    if (k == Param.SCOPE) {
                        when (v) {
                            is Collection<*> -> v.map { it.toString() }.filter { it.isNotBlank() }.let { b.addRequestScope(it) }
                            is String -> v.split(Misc.SPACE).filter { it.isNotBlank() }.let { b.addRequestScope(it) }
                            else -> TODO("scope can only be list or string claim")
                        }
                    } else {
                        b.addRequestParameter(k to v.toString())
                    }
                }
            }.also { b ->
                b.client = deferredClient.await()
            }
            .build()
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