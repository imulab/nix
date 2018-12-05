package io.imulab.nix.server.config

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.client.authn.ClientSecretBasicAuthenticator
import io.imulab.nix.oauth.client.authn.ClientSecretPostAuthenticator
import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import io.imulab.nix.oauth.client.pwd.PasswordEncoder
import io.imulab.nix.oauth.reserved.AuthenticationMethod
import io.imulab.nix.oidc.client.authn.PrivateKeyJwtAuthenticator
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ClientConfiguration {

    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder()

    @Bean
    fun secretBasicAuthenticator(lookup: ClientLookup, passwordEncoder: PasswordEncoder) =
        ClientSecretBasicAuthenticator(lookup = lookup, passwordEncoder = passwordEncoder)

    @Bean
    fun secretPostAuthenticator(lookup: ClientLookup, passwordEncoder: PasswordEncoder) =
        ClientSecretPostAuthenticator(lookup = lookup, passwordEncoder = passwordEncoder)

    @Bean
    fun privateKeyJwtAuthenticator(
        lookup: ClientLookup,
        nixProperties: NixProperties,
        jwksStrategy: JsonWebKeySetStrategy
    ) = PrivateKeyJwtAuthenticator(
        clientLookup = lookup,
        oauthContext = nixProperties,
        clientJwksStrategy = jwksStrategy
    )

    @Bean
    fun clientAuthenticator(
        secretBasic: ClientSecretBasicAuthenticator,
        secretPost: ClientSecretPostAuthenticator,
        privateKeyJwt: PrivateKeyJwtAuthenticator
    ) = ClientAuthenticators(
        authenticators = listOf(secretBasic, secretPost, privateKeyJwt),
        defaultMethod = AuthenticationMethod.clientSecretPost
    )
}