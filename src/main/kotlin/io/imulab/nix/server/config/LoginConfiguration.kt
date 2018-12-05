package io.imulab.nix.server.config

import io.imulab.nix.server.authz.authn.*
import io.imulab.nix.server.authz.authn.obfs.SubjectObfuscator
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringWebSessionStrategy
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment

/**
 * This class configures all authentication/login related components (minus state management).
 */
@Configuration
class LoginConfiguration @Autowired constructor(
    private val properties: NixProperties,
    private val environment: Environment,
    private val oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository
) {

    @Bean
    fun loginTokenStrategy() = LoginTokenStrategy(
        oidcContext = properties,
        tokenAudience = properties.endpoints.login,
        tokenLifespan = properties.loginToken.expiration
    )

    @Bean
    fun authenticationProvider(loginTokenStrategy: LoginTokenStrategy) = AuthenticationProvider(
        handlers = mutableListOf(
            LoginTokenAuthenticationHandler(loginTokenStrategy, SpringWebSessionStrategy),
            IdTokenHintAuthenticationHandler(properties),
            SessionAuthenticationHandler(SpringWebSessionStrategy)
        ).apply {
            if (environment.getProperty("nix.security.autoLogin", Boolean::class.java, false))
                add(AutoLoginAuthenticationHandler())
        },
        loginTokenStrategy = loginTokenStrategy,
        loginProviderEndpoint = properties.endpoints.login,
        oidcContext = properties,
        requestRepository = oidcAuthorizeRequestRepository,
        subjectObfuscator = SubjectObfuscator(properties.security.subjectSalt.toByteArray())
    )
}