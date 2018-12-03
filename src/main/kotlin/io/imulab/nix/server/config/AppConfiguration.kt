package io.imulab.nix.server.config

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.discovery.Discovery
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.request.CachedRequestRepository
import io.imulab.nix.oidc.request.OidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.RequestObjectAwareOidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.RequestStrategy
import io.imulab.nix.oidc.validation.OidcResponseTypeValidator
import io.imulab.nix.server.authz.ResumeOidcAuthorizeRequestProducer
import io.imulab.nix.server.authz.authn.*
import io.imulab.nix.server.authz.authn.obfs.SubjectObfuscator
import io.imulab.nix.server.authz.consent.*
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringHttpClient
import io.imulab.nix.server.http.SpringWebSessionStrategy
import io.imulab.nix.server.oidc.GsonClaimsConverter
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order

@Configuration
class AppConfiguration {

    @Bean
    fun jwksStrategy(jwksRepo: JsonWebKeySetRepository) = JsonWebKeySetStrategy(
        jsonWebKeySetRepository = jwksRepo,
        httpClient = SpringHttpClient
    )

    @Bean
    fun requestStrategy(
        cachedRequestRepository: CachedRequestRepository,
        jwksStrategy: JsonWebKeySetStrategy,
        oidcContext: OidcContext
    ) = RequestStrategy(
        repository = cachedRequestRepository,
        httpClient = SpringHttpClient,
        jsonWebKeySetStrategy = jwksStrategy,
        serverContext = oidcContext
    )

    @Bean
    fun requestProducer(
        oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
        discovery: Discovery,
        requestStrategy: RequestStrategy,
        clientLookup: ClientLookup
    ) = ResumeOidcAuthorizeRequestProducer(
        oidcAuthorizeRequestRepository = oidcAuthorizeRequestRepository,
        defaultProducer = RequestObjectAwareOidcAuthorizeRequestProducer(
            discovery = discovery,
            claimsJsonConverter = GsonClaimsConverter,
            requestStrategy = requestStrategy,
            firstPassProducer = OidcAuthorizeRequestProducer(
                lookup = clientLookup,
                claimsJsonConverter = GsonClaimsConverter,
                responseTypeValidator = OidcResponseTypeValidator
            )
        )
    )

    @Bean
    fun subjectObfuscator(prop: NixProperties) =
        SubjectObfuscator(pairwiseSalt = prop.security.subjectSalt.toByteArray())

    @Bean
    fun loginTokenStrategy(prop: NixProperties) = LoginTokenStrategy(
        oidcContext = prop,
        tokenAudience = prop.endpoints.login
    )

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun loginTokenAuthenticator(
        loginTokenStrategy: LoginTokenStrategy
    ) = LoginTokenAuthenticationHandler(
        loginTokenStrategy = loginTokenStrategy,
        sessionStrategy = SpringWebSessionStrategy
    )

    @Bean
    @Order(0)
    fun sessionAuthenticator() = SessionAuthenticationHandler(
        sessionStrategy = SpringWebSessionStrategy
    )

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    @ConditionalOnProperty(value = ["nix.security.autoLogin"], havingValue = "true")
    fun autoLoginAuthenticator() = AutoLoginAuthenticationHandler()

    @Bean
    fun authenticationProvider(
        handlers: List<AuthenticationHandler>,
        oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
        subjectObfuscator: SubjectObfuscator,
        loginTokenStrategy: LoginTokenStrategy,
        prop: NixProperties
    ) = AuthenticationProvider(
        handlers = handlers,
        loginTokenStrategy = loginTokenStrategy,
        loginProviderEndpoint = prop.endpoints.login,
        oidcContext = prop,
        requestRepository = oidcAuthorizeRequestRepository,
        subjectObfuscator = subjectObfuscator
    )

    @Bean
    fun consentTokenStrategy(prop: NixProperties) = ConsentTokenStrategy(
        oidcContext = prop,
        tokenAudience = prop.endpoints.consent,
        claimsJsonConverter = GsonClaimsConverter
    )

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun consentTokenConsentHandler(
        consentTokenStrategy: ConsentTokenStrategy
    ) = ConsentTokenConsentHandler(
        consentTokenStrategy = consentTokenStrategy,
        sessionStrategy = SpringWebSessionStrategy
    )

    @Bean
    @Order(0)
    fun sessionConsentHandler() = SessionConsentHandler(sessionStrategy = SpringWebSessionStrategy)

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    @ConditionalOnProperty(value = ["nix.security.autoConsent"], havingValue = "true")
    fun autoGrantConsentHandler() = AutoGrantConsentHandler()

    @Bean
    fun consentProvider(
        handlers: List<ConsentHandler>,
        oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
        consentTokenStrategy: ConsentTokenStrategy,
        prop: NixProperties
    ) = ConsentProvider(
        handlers = handlers,
        requestRepository = oidcAuthorizeRequestRepository,
        oidcContext = prop,
        consentTokenStrategy = consentTokenStrategy,
        requireAuthentication = true,
        consentProviderEndpoint = prop.endpoints.consent
    )
}