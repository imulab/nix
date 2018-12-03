package io.imulab.nix.server.config

import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.token.JwxIdTokenStrategy
import io.imulab.nix.server.http.SpringHttpClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * This class configures everything related to OIDC.
 */
@Configuration
class OidcConfiguration {

    /**
     * A [JsonWebKeySetStrategy] bean. This bean is responsible for resolving a Json Web Key Set for a client.
     */
    @Bean
    fun jwksStrategy(jwksRepo: JsonWebKeySetRepository) = JsonWebKeySetStrategy(
        jsonWebKeySetRepository = jwksRepo,
        httpClient = SpringHttpClient
    )

    /**
     * A [JwxIdTokenStrategy] bean. This bean is responsible for generating an id token.
     */
    @Bean
    fun idTokenStrategy(
        nixProperties: NixProperties,
        jwksStrategy: JsonWebKeySetStrategy
    ) = JwxIdTokenStrategy(
        oidcContext = nixProperties,
        jsonWebKeySetStrategy = jwksStrategy
    )
}