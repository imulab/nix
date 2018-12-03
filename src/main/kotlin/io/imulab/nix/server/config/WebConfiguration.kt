package io.imulab.nix.server.config

import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.imulab.nix.server.route.AuthorizeRouteProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
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
    fun oidcRoutes(provider: AuthorizeRouteProvider): RouterFunction<ServerResponse> = route()
        .path("/oauth") { b ->
            b.GET("/authorize", provider::handle)
        }.build()

    /**
     * A [AuthorizeRouteProvider] bean. This bean is responsible for handling traffic directly to
     * `/oauth/authorize` endpoint.
     */
    @Bean
    fun authorizeRouteProvider(
        requestProducer: OAuthRequestProducer,
        authenticationProvider: AuthenticationProvider,
        consentProvider: ConsentProvider
    ) = AuthorizeRouteProvider(
        requestProducer = requestProducer,
        authenticationProvider = authenticationProvider,
        consentProvider = consentProvider
    )
}