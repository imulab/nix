package io.imulab.nix.server.route

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.response.OAuthResponse
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.reserved.ResponseMode
import io.imulab.nix.oidc.response.OidcAuthorizeEndpointResponse
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.authn.LoginRedirectionSignal
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.imulab.nix.server.authz.consent.ConsentRedirectionSignal
import kotlinx.coroutines.runBlocking
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

class AuthorizeRouteProvider(
    private val requestProducer: OAuthRequestProducer,
    private val preValidation: OAuthRequestValidation,
    private val authenticationProvider: AuthenticationProvider,
    private val consentProvider: ConsentProvider,
    private val handlers: List<AuthorizeRequestHandler>,
    private val postValidation: OAuthRequestValidation
) {

    fun handle(request: ServerRequest): Mono<ServerResponse> {
        val form = Mono.just(request)
            .flatMap {
                when (it.method()) {
                    HttpMethod.GET -> Mono.just(it.queryParams())
                    HttpMethod.POST -> it.formData()
                    else -> throw IllegalStateException("Invalid request method.")
                }
            }
            .map { OidcRequestForm(it) }

        val parsedRequest = form.map {
            runBlocking {
                requestProducer.produce(it).assertType<OidcAuthorizeRequest>()
            }
        }

        val preValidated = parsedRequest.map { it.apply { preValidation.validate(this) } }

        val authorized = form.zipWith(preValidated).zipWith(request.session())
            .map {
                runBlocking {
                    authenticationProvider.tryAuthenticate(it.t1.t1, it.t1.t2.assertType(), it.t2)
                    consentProvider.tryAuthorize(it.t1.t1, it.t1.t2.assertType(), it.t2)
                    return@runBlocking it.t1.t2
                }
            }

        val postValidated = authorized.map { it.apply { postValidation.validate(this) } }

        val handled: Mono<OAuthResponse> = postValidated
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

        return handled
            .onErrorResume { t -> Mono.just(t.asOAuthResponse()) }
            .flatMap { resp ->
                parsedRequest.flatMap { r -> resp.render(r.responseMode, r.redirectUri) }
                    .onErrorResume { t -> t.asOAuthResponse().render() }
            }
    }

    private fun OAuthResponse.render(
        responseMode: String = ResponseMode.query,
        redirectUri: String = ""
    ): Mono<ServerResponse> {
        return when {
            this is LoginRedirectionSignal -> renderRedirectWithQueries(loginEndpoint)
            this is ConsentRedirectionSignal -> renderRedirectWithQueries(consentEndpoint)
            redirectUri.isEmpty() -> ServerResponse.badRequest().syncBody(data)
            responseMode == ResponseMode.fragment -> renderRedirectWithFragments(redirectUri)
            else -> renderRedirectWithQueries(redirectUri)
        }
    }

    private fun OAuthResponse.renderRedirectWithQueries(redirectUri: String): Mono<ServerResponse> {
        return ServerResponse.status(HttpStatus.FOUND).location(
            UriComponentsBuilder
                .fromUriString(redirectUri)
                .also { b -> data.keys.forEach { k -> b.query("$k={$k}") } }
                .buildAndExpand(data)
                .encode()
                .toUri()
        ).build()
    }

    private fun OAuthResponse.renderRedirectWithFragments(redirectUri: String): Mono<ServerResponse> {
        val fragment = UriComponentsBuilder
            .fromUriString(redirectUri)
            .also { b -> data.keys.forEach { k -> b.query("$k={$k}") } }
            .buildAndExpand(data)
            .encode().query
        return ServerResponse.status(HttpStatus.FOUND)
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

    private fun Throwable.asOAuthResponse(): OAuthResponse {
        return when (this) {
            is OAuthResponse -> this
            else -> ServerError.wrapped(this)
        }
    }
}