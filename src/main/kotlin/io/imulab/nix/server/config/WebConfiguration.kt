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

@Configuration
@EnableWebFlux
class WebConfiguration : WebFluxConfigurer {

    @Bean
    fun oidcRoutes(provider: AuthorizeRouteProvider): RouterFunction<ServerResponse> = route()
        .path("/oauth") { b ->
            b.GET("/authorize", provider::handle)
        }.build()

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