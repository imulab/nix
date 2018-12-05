package io.imulab.nix.server.route

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.response.OAuthResponse
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.reserved.ResponseMode
import io.imulab.nix.oidc.response.OidcAuthorizeEndpointResponse
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.ktor.routing.Routing
import io.ktor.routing.get
import kotlinx.coroutines.runBlocking
import org.kodein.di.Kodein
import org.kodein.di.erased.instance
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

fun Routing.authorize(di: Kodein) {
    get("/oauth/authorize") {
        val provider: AuthorizeRouteProvider by di.instance()
        //provider.accept(this)
    }
}

class AuthorizeRouteProvider(
    private val requestProducer: OAuthRequestProducer,
    //private val preValidation: OAuthRequestValidation,
    private val authenticationProvider: AuthenticationProvider,
    private val consentProvider: ConsentProvider,
    private val handlers: List<AuthorizeRequestHandler>
    //private val postValidation: OAuthRequestValidation
) {

    fun handle(request: ServerRequest): Mono<ServerResponse> {
        val formMono = Mono.just(request)
            .flatMap {
                return@flatMap when (it.method()) {
                    HttpMethod.GET -> Mono.just(it.queryParams())
                    HttpMethod.POST -> it.formData()
                    else -> throw IllegalStateException("Invalid request method.")
                }
            }
            .map { OidcRequestForm(it) }

        val requestMono = formMono.map {
            runBlocking {
                requestProducer.produce(it).assertType<OidcAuthorizeRequest>()
            }
        }

        // we need pre-validation

        val authorizedMono = formMono.zipWith(requestMono).zipWith(request.session())
            .map {
                runBlocking {
                    authenticationProvider.tryAuthenticate(it.t1.t1, it.t1.t2.assertType(), it.t2)
                    consentProvider.tryAuthorize(it.t1.t1, it.t1.t2.assertType(), it.t2)
                    return@runBlocking it.t1.t2
                }
            }

        // we need post-validation

        val handledMono: Mono<OAuthResponse> = authorizedMono
            .map {
                runBlocking {
                    val response = OidcAuthorizeEndpointResponse()
                    for (h in handlers)
                        h.handleAuthorizeRequest(it, response)
                    if (!response.handledResponseTypes.containsAll(it.responseTypes))
                        throw ServerError.internal("Some response types were not handled.")
                    return@runBlocking response as OAuthResponse
                }
            }

        val r = handledMono
            .onErrorResume { t -> Mono.just(t.asOAuthResponse()) }
            .flatMap { resp ->
                //resp.render("fragment", "http://localhost:8888/callback")

                formMono.flatMap { f ->
                    resp.render(f.responseMode, f.redirectUri)
                }

                requestMono.flatMap { r -> resp.render(r.responseMode, r.redirectUri) }
                    .onErrorResume { t -> t.asOAuthResponse().render("", "") }

//                requestMono.flatMap { req ->
//                    resp.render(req.responseMode, req.redirectUri)
//                }.onErrorResume { t -> Mono.just(ServerError.wrapped(t)) }
            }
            /*.onErrorResume { t ->
                val e: OAuthResponse = when (t) {
                    is OAuthResponse -> t
                    else -> ServerError.wrapped(t)
                }
                requestMono.flatMap { req ->
                    e.render(req.responseMode, req.redirectUri)
                }
            }*/

        return r
    }

    private fun Throwable.asOAuthResponse(): OAuthResponse {
        return when (this) {
            is OAuthResponse -> this
            else -> ServerError.wrapped(this)
        }
    }

    private fun OAuthResponse.render(responseMode: String, redirectUri: String): Mono<ServerResponse> {
        if (redirectUri.isEmpty())
            return ServerResponse.badRequest().syncBody(this.data)

        return when (responseMode) {
            ResponseMode.fragment -> {
                val fragment = UriComponentsBuilder
                    .fromUriString(redirectUri)
                    .also { b -> data.keys.forEach { k -> b.query("$k={$k}") } }
                    .buildAndExpand(data)
                    .encode().query
                ServerResponse.status(HttpStatus.FOUND)
                    .location(
                        UriComponentsBuilder
                            .fromUriString(redirectUri)
                            .fragment(fragment)
                            .build()
                            .encode()
                            .toUri()
                    )
                    .build()
            }
            else -> {
                ServerResponse.status(HttpStatus.FOUND)
                    .location(
                        UriComponentsBuilder
                            .fromUriString(redirectUri)
                            .also { b ->
                                data.keys.forEach { k -> b.query("$k={$k}") }
                            }
                            .buildAndExpand(data)
                            .encode()
                            .toUri()
                    )
                    .build()
            }
        }
    }

//    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
//        try {
//            doAccept(ctx)
//        } catch (e: Exception) {
//            when (e) {
//                is LoginRedirectionSignal -> {
//
//                }
//                is ConsentRedirectionSignal -> {
//
//                }
//                is OAuthException -> {
//
//                }
//                else -> {
//
//                }
//            }
//        }
//    }
//
//    private suspend fun doAccept(ctx: PipelineContext<Unit, ApplicationCall>) {
//        val requestForm =
//            OidcRequestForm(httpForm = ctx.context.autoParameters().toMutableMap())
//
//        val authorizeRequest = requestProducer.produce(requestForm).assertType<OidcAuthorizeRequest>()
//
//        // next up: preliminary validation, skip validation related to session.
//        preValidation.validate(authorizeRequest)
//
//        // authentication
//        authenticationProvider.tryAuthenticate(requestForm, authorizeRequest, ctx.call)
//
//        // consent
//        consentProvider.tryAuthorize(requestForm, authorizeRequest, ctx.call)
//
//        // post validation (everything should be nice and sound)
//        postValidation.validate(authorizeRequest)
//
//        // handlers
//
//        // render response
//
//        println(requestForm.clientId)
//    }
}