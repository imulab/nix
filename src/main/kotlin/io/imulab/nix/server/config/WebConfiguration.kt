package io.imulab.nix.server.config

import io.imulab.nix.oauth.handler.OAuthAuthorizeCodeHandler
import io.imulab.nix.oauth.handler.OAuthClientCredentialsHandler
import io.imulab.nix.oauth.handler.OAuthImplicitHandler
import io.imulab.nix.oauth.handler.OAuthRefreshHandler
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.imulab.nix.server.route.AuthorizeRouteProvider
import io.imulab.nix.server.route.TokenRouteProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.session.ReactiveMapSessionRepository
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.HandlerFunction
import org.springframework.web.reactive.function.server.RequestPredicates.contentType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.RouterFunctions.route
import org.springframework.web.reactive.function.server.ServerResponse
import java.util.concurrent.ConcurrentHashMap

/**
 * This class configures the web component of the server.
 */
@Configuration
@EnableWebFlux
class WebConfiguration @Autowired constructor(
    @Qualifier("authorizeRequestProducer")
    private val authorizeRequestProducer: OAuthRequestProducer,
    private val authenticationProvider: AuthenticationProvider,
    private val consentProvider: ConsentProvider,
    private val oAuthAuthorizeCodeHandler: OAuthAuthorizeCodeHandler,
    private val oAuthImplicitHandler: OAuthImplicitHandler,
    private val oAuthClientCredentialsHandler: OAuthClientCredentialsHandler,
    private val oAuthRefreshHandler: OAuthRefreshHandler,
    @Qualifier("accessRequestProducer")
    private val accessRequestProducer: OAuthRequestProducer
) : WebFluxConfigurer {

    @Bean @Memory
    fun webSessionRepository() = ReactiveMapSessionRepository(ConcurrentHashMap())

    @Bean
    fun routes(authorize: AuthorizeRouteProvider, access: TokenRouteProvider): RouterFunction<ServerResponse> = route()
        .GET("/oauth/authorize", HandlerFunction(authorize::handle))
        .POST("/oauth/token", contentType(APPLICATION_FORM_URLENCODED), HandlerFunction(access::handle))
        .build()

    @Bean
    fun authorizeRouteProvider() = AuthorizeRouteProvider(
        requestProducer = authorizeRequestProducer,
        authenticationProvider = authenticationProvider,
        consentProvider = consentProvider,
        handlers = listOf(
            oAuthAuthorizeCodeHandler,
            oAuthImplicitHandler
        )
    )

    @Bean
    fun tokenRouteProvider() = TokenRouteProvider(
        requestProducer = accessRequestProducer,
        handlers = listOf(
            oAuthAuthorizeCodeHandler,
            oAuthClientCredentialsHandler,
            oAuthRefreshHandler
        )
    )
}