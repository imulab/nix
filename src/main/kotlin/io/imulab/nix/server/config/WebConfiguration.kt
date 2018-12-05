package io.imulab.nix.server.config

import io.imulab.nix.oauth.handler.AccessRequestHandler
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.imulab.nix.server.route.AuthorizeRouteProvider
import io.imulab.nix.server.route.TokenRouteProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.HandlerFunction
import org.springframework.web.reactive.function.server.RequestPredicates.contentType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.RouterFunctions.route
import org.springframework.web.reactive.function.server.ServerResponse

/**
 * This class configures the web component of the server.
 */
@Configuration
@EnableWebFlux
class WebConfiguration : WebFluxConfigurer {

    /**
     * All OAuth defined routes.
     */
    @Bean
    fun routes(
        authorizeProvider: AuthorizeRouteProvider,
        accessProvider: TokenRouteProvider
    ): RouterFunction<ServerResponse> = route()
        .path("/oauth") { b ->
            b.GET("/authorize", HandlerFunction(authorizeProvider::handle))
            b.POST("/token", contentType(MediaType.APPLICATION_FORM_URLENCODED), HandlerFunction(accessProvider::handle))
        }.build()

    /**
     * A [AuthorizeRouteProvider] bean. This bean is responsible for handling traffic directly to
     * `/oauth/authorize` endpoint.
     */
    @Bean
    fun authorizeRouteProvider(
        @Qualifier("authorizeRequestProducer")
        requestProducer: OAuthRequestProducer,
        authenticationProvider: AuthenticationProvider,
        consentProvider: ConsentProvider,
        handlers: List<AuthorizeRequestHandler>
    ) = AuthorizeRouteProvider(
        requestProducer = requestProducer,
        authenticationProvider = authenticationProvider,
        consentProvider = consentProvider,
        handlers = handlers
    )

    /**
     * A [TokenRouteProvider] bean. This bean is responsible for handling traffic directly to the
     * `/oauth/token` endpoint.
     */
    @Bean
    fun tokenRouteProvider(
        @Qualifier("accessRequestProducer")
        requestProducer: OAuthRequestProducer,
        handlers: List<AccessRequestHandler>
    ) = TokenRouteProvider(
        requestProducer = requestProducer,
        handlers = handlers
    )
}