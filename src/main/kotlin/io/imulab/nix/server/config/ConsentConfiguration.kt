package io.imulab.nix.server.config

import io.imulab.nix.server.authz.consent.*
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringWebSessionStrategy
import io.imulab.nix.server.oidc.GsonClaimsConverter
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order

/**
 * This class configures all authorization/consent related components (minus state management).
 */
@Configuration
class ConsentConfiguration {

    /**
     * A [ConsentTokenStrategy] bean. This bean is responsible of generating `consent_token` request and decoding
     * `consent_token` response.
     */
    @Bean
    fun consentTokenStrategy(prop: NixProperties) = ConsentTokenStrategy(
        oidcContext = prop,
        tokenAudience = prop.endpoints.consent,
        claimsJsonConverter = GsonClaimsConverter
    )

    /**
     * A [ConsentTokenConsentHandler] bean. This bean is responsible of inspecting and determining authorization
     * status depending on the information decoded by [ConsentTokenStrategy].
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun consentTokenConsentHandler(
        consentTokenStrategy: ConsentTokenStrategy
    ) = ConsentTokenConsentHandler(
        consentTokenStrategy = consentTokenStrategy,
        sessionStrategy = SpringWebSessionStrategy
    )

    /**
     * A [SessionConsentHandler] bean. This bean is responsible of determining authorization status using
     * session cookie.
     */
    @Bean
    @Order(0)
    fun sessionConsentHandler() = SessionConsentHandler(sessionStrategy = SpringWebSessionStrategy)

    /**
     * A [AutoGrantConsentHandler] bean. This bean automatically grants all requested scopes and optionally
     * sets a fixed set of claims on request session.
     *
     * **This bean is not supposed to be used in production environment.**
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    @ConditionalOnProperty(value = ["nix.security.autoConsent"], havingValue = "true")
    fun autoGrantConsentHandler() = AutoGrantConsentHandler()

    /**
     * A [ConsentProvider] bean. This bean is responsible of ultimately request and determine user's
     * authorization/consent status. A request either fails with this bean due to `interaction_required` error, or
     * passes this bean with scopes granted and/or claims set on session.
     */
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