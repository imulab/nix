package deprecated.route

import deprecated.client.OAuthClient
import deprecated.client.OidcClient
import deprecated.client.manager.ClientStore
import deprecated.constant.Error
import deprecated.constant.Param
import deprecated.constant.Scope
import deprecated.oauth.request.AuthorizeRequest
import deprecated.oauth.request.NixAuthorizeRequest.Companion.Builder
import deprecated.oauth.session.Session
import deprecated.oauth.token.strategy.RequestObjectStrategy
import deprecated.oauth.vor.JsonWebKeySetVor
import deprecated.oauth.vor.RequestObjectVor
import deprecated.support.*
import io.imulab.nix.support.*
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.routing.Routing
import io.ktor.routing.get
import kotlinx.coroutines.*
import org.jose4j.jwk.JsonWebKeySet
import org.kodein.di.Kodein
import org.kodein.di.erased.instance

fun Routing.authorize(kodein: Kodein) {
    get("/oauth/authorize") {
        val routeHandler: OAuthAuthorizationRouteHandler by kodein.instance()
        withContext(Dispatchers.Default) {
            runBlocking { routeHandler.handleRequest(call) }
        }
    }
}

class OAuthAuthorizationRouteHandler(
    private val clientStore: ClientStore,
    private val stateEntropy: Int = 8,
    private val tokenIssuer: String,
    private val requestObjectVor: RequestObjectVor,
    private val requestObjectStrategy: RequestObjectStrategy,
    private val jsonWebKeySetVor: JsonWebKeySetVor,
    private val serverJsonWebKeySet: JsonWebKeySet
) {

    suspend fun handleRequest(call: ApplicationCall) {
        try {
            val authorizeRequest = createAuthorizeRequest(call)
        } catch (e: Exception) {

        }
    }

    private suspend fun createAuthorizeRequest(call: ApplicationCall): AuthorizeRequest {
        val builder = Builder().also { b ->
            b.requestForm = call.parseRequestForm().toMutableMap()
        }

        val deferredClient = withContext(Dispatchers.IO) {
            async { clientStore.getClient(builder.requestForm.mustClientId()) }
        }

        return builder.also { b ->
            if (b.requestForm.scopes().contains(Scope.OPENID))
                expandOidcRequestObject(b, deferredClient)
            populateOAuthParameters(b, deferredClient.await())
        }.build()
    }

    private fun populateOAuthParameters(builder: Builder, c: OAuthClient) = with(builder) {
        requireNotNull(requestForm)
        client = c
        redirectUri = requestForm.redirectUri().let { formUri ->
            if (formUri.isBlank()) {
                when (c.redirectUris.size) {
                    1 -> c.redirectUris[0].asValid()
                    0 -> throw Error.RedirectUri.noneRegistered()
                    else -> throw Error.RedirectUri.multipleRegistered()
                }
            } else {
                if (c.redirectUris.contains(redirectUri))
                    formUri.asValid()
                else
                    throw Error.RedirectUri.rouge()
            }
        }
        state = requestForm.state().also { s ->
            if (s.isEmpty())
                throw Error.State.missing()
            if (s.length < stateEntropy)
                throw Error.State.entropy()
        }
        addResponseType(requestForm.responseTypes())
        addRequestScope(requestForm.scopes())
        session = Session()
    }

    /**
     * Decode (optionally decrypt first) the open id connect object request contained in the 'request' or 'request_uri'
     * parameter. Then merge the claimed fields back into the request as parameters. Downstream processing can view
     * open id connect request and oauth request in a unified manner.
     *
     * This method assumes any content provided via 'redirect_uri' has already been resolved and assigned to 'request'
     * parameter in the container, hence it only takes into account the 'request' parameter in the container.
     *
     * Claims from the request object is considered fixed, hence any parameters supplied from url queries takes precedence.
     *
     * If a parameter is supplied from both url queries and in request object. When the parameter type is simple
     * string (for instance, the state parameter), request object parameter will be ignored. When the parameter type
     * can be effectively merged (for instance, the scope parameter which is a space delimited list), the request object
     * parameter will be merged back into the url query parameters.
     *
     * Any parameter which is present in the request object but not from the url queries are retained.
     */
    private suspend fun expandOidcRequestObject(builder: Builder, client: Deferred<OAuthClient>) = with(builder) {
        if (!requestForm.scopes().contains(Scope.OPENID))
            return@with

        val request = requestObjectVor.resolve(requestForm.request(), requestForm.requestUri(), null)
            ?.also { requestForm[Param.REQUEST] = it }
            ?: throw Error.RequestObject.acquireFailed()

        requestObjectStrategy.resolveRequestObject(request, client.await() as OidcClient).jwtClaims.let { c ->
            requestForm.run {
                listOf(
                    Param.REDIRECT_URI,
                    Param.STATE,
                    Param.NONCE,
                    Param.RESPONSE_MODE,                    // TODO not used or validated
                    Param.DISPLAY,                          // TODO not used or validated
                    Param.MAX_AGE,
                    Param.UI_LOCALES,                       // TODO not used or validated
                    Param.CLAIMS_LOCALES,                   // TODO not used or validated
                    Param.ID_TOKEN_HINT,
                    Param.LOGIN_HINT,                        // TODO not used or validated
                    Param.CLAIMS                             // TODO not used or validated
                ).forEach { p -> switchIfEmpty(p, c.maybe(p)) }

                listOf(
                    Param.RESPONSE_TYPE,
                    Param.SCOPE,
                    Param.PROMPT,
                    Param.ACR_VALUES                        // TODO not used or validated
                ).forEach { p -> merge(p, c.maybe(p)) }
            }
        }
    }
}