package io.imulab.nix.server.config

import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.server.authz.authn.*
import io.imulab.nix.server.authz.authn.obfs.SubjectObfuscator
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringWebSessionStrategy
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order

/**
 * This class configures all authentication/login related components (minus state management).
 */
@Configuration
class LoginConfiguration {

    /**
     * A [SubjectObfuscator] bean. This bean is used to obfuscate subject identifier so that a group
     * of clients cannot correlate subjects without authorization.
     */
    @Bean
    fun subjectObfuscator(prop: NixProperties) =
        SubjectObfuscator(pairwiseSalt = prop.security.subjectSalt.toByteArray())

    /**
     * A [LoginTokenStrategy] bean. This bean is responsible for generating a `login_token` request and
     * decoding a `login_token` response.
     */
    @Bean
    fun loginTokenStrategy(prop: NixProperties) = LoginTokenStrategy(
        oidcContext = prop,
        tokenAudience = prop.endpoints.login
    )

    /**
     * A [LoginTokenAuthenticationHandler] bean. This bean is responsible of inspecting the information
     * decoded by [LoginTokenStrategy] and determine the user's authentication status.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun loginTokenAuthenticator(
        loginTokenStrategy: LoginTokenStrategy
    ) = LoginTokenAuthenticationHandler(
        loginTokenStrategy = loginTokenStrategy,
        sessionStrategy = SpringWebSessionStrategy
    )

    /**
     * A [IdTokenHintAuthenticator] bean. This bean is responsible of determining authentication status
     * from a `id_token_hint`.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    fun IdTokenHintAuthenticator(oidcContext: OidcContext) =
        IdTokenHintAuthenticationHandler(oidcContext = oidcContext)

    /**
     * A [SessionAuthenticationHandler] bean. This bean is responsible of determining user's authentication
     * status using session cookie.
     */
    @Bean
    @Order(0)
    fun sessionAuthenticator() = SessionAuthenticationHandler(
        sessionStrategy = SpringWebSessionStrategy
    )

    /**
     * A [AutoLoginAuthenticationHandler] bean. This bean is responsible of automatically login a fixed user.
     * It is only loaded when `nix.security.autoLogin` configuration option is set to `true`.
     *
     * **It is not supposed to by part of a production system**.
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    @ConditionalOnProperty(value = ["nix.security.autoLogin"], havingValue = "true")
    fun autoLoginAuthenticator() = AutoLoginAuthenticationHandler()

    /**
     * A [AuthenticationProvider] bean. This bean is responsible of ultimately request and determine user's
     * authentication status. A request either fails with this bean due to `login_required` error, or passes
     * this bean with authentication status set on session.
     */
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
}