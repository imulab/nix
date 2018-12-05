package io.imulab.nix.server.config

import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.request.MemoryOidcSessionRepository
import io.imulab.nix.oidc.token.JwxIdTokenStrategy
import io.imulab.nix.server.http.SpringHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * This class configures everything related to OIDC.
 */
@Configuration
class OidcConfiguration @Autowired constructor(private val properties: NixProperties) {

    @Bean @Memory
    fun oidcSessionRepository() = MemoryOidcSessionRepository()

    @Bean
    fun jwksStrategy(repo: JsonWebKeySetRepository) = JsonWebKeySetStrategy(repo, SpringHttpClient)

    @Bean
    fun idTokenStrategy(strategy: JsonWebKeySetStrategy) = JwxIdTokenStrategy(properties, strategy)
}