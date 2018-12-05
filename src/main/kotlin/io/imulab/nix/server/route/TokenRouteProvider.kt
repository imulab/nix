package io.imulab.nix.server.route

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.handler.AccessRequestHandler
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.response.OAuthResponse
import io.imulab.nix.oauth.validation.OAuthRequestValidationChain
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.response.OidcTokenEndpointResponse
import kotlinx.coroutines.runBlocking
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

class TokenRouteProvider(
    private val requestProducer: OAuthRequestProducer,
    private val validator: OAuthRequestValidationChain,
    private val handlers: List<AccessRequestHandler>
) {

    fun handle(request: ServerRequest): Mono<ServerResponse> {
        val form = Mono.just(request)
            .flatMap { it.formData() }
            .map { OidcRequestForm(it) }

        val parsedRequest = form.map {
            runBlocking {
                requestProducer.produce(it).assertType<OAuthAccessRequest>()
            }
        }

        val validated = parsedRequest.map { it.apply { validator.validate(this) } }

        val handled: Mono<OAuthResponse> = validated
            .map {
                runBlocking {
                    val response = OidcTokenEndpointResponse()
                    for (h in handlers)
                        h.updateSession(it)
                    for (h in handlers)
                        h.handleAccessRequest(it, response)
                    return@runBlocking response
                }
            }

        return handled
            .onErrorResume { t -> Mono.just(t.asOAuthResponse()) }
            .flatMap { resp -> resp.render() }
    }

    private fun OAuthResponse.render(): Mono<ServerResponse> {
        return ServerResponse.status(status).also {
            headers.forEach { t, u -> it.header(t, u) }
        }.syncBody(data)
    }

    private fun Throwable.asOAuthResponse(): OAuthResponse {
        return when (this) {
            is OAuthResponse -> this
            else -> ServerError.wrapped(this)
        }
    }
}