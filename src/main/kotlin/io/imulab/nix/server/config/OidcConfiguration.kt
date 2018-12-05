package io.imulab.nix.server.config

import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.token.storage.AuthorizeCodeRepository
import io.imulab.nix.oauth.token.strategy.AuthorizeCodeStrategy
import io.imulab.nix.oidc.handler.OidcAuthorizeCodeHandler
import io.imulab.nix.oidc.handler.OidcHybridHandler
import io.imulab.nix.oidc.handler.OidcImplicitHandler
import io.imulab.nix.oidc.handler.OidcRefreshHandler
import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.request.MemoryOidcSessionRepository
import io.imulab.nix.oidc.request.OidcSessionRepository
import io.imulab.nix.oidc.token.IdTokenStrategy
import io.imulab.nix.oidc.token.JwxIdTokenStrategy
import io.imulab.nix.server.http.SpringHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * This class configures everything related to OIDC.
 */
@Configuration
class OidcConfiguration @Autowired constructor(
    private val properties: NixProperties,
    private val accessTokenHelper: AccessTokenHelper,
    private val authorizeCodeStrategy: AuthorizeCodeStrategy,
    private val authorizeCodeRepository: AuthorizeCodeRepository
) {

    @Bean @Memory
    fun oidcSessionRepository() = MemoryOidcSessionRepository()

    @Bean
    fun jwksStrategy(repo: JsonWebKeySetRepository) = JsonWebKeySetStrategy(repo, SpringHttpClient)

    @Bean
    fun idTokenStrategy(strategy: JsonWebKeySetStrategy) = JwxIdTokenStrategy(properties, strategy)

    @Bean
    fun oidcAuthorizeCodeHandler(strategy: IdTokenStrategy, repo: OidcSessionRepository) =
        OidcAuthorizeCodeHandler(strategy, repo)

    @Bean
    fun oidcImplicitHandler(strategy: IdTokenStrategy) = OidcImplicitHandler(accessTokenHelper, strategy)

    @Bean
    fun oidcHybridHandler(
        authHandler: OidcAuthorizeCodeHandler,
        idTokenStrategy: IdTokenStrategy,
        sessionRepository: OidcSessionRepository
    ) = OidcHybridHandler(
        authHandler,
        authorizeCodeStrategy,
        authorizeCodeRepository,
        idTokenStrategy,
        accessTokenHelper,
        sessionRepository
    )

    @Bean
    fun oidcRefreshHandler(idTokenStrategy: IdTokenStrategy) = OidcRefreshHandler(idTokenStrategy)
}