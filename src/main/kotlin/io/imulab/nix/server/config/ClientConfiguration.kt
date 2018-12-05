package io.imulab.nix.server.config

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.client.authn.ClientSecretBasicAuthenticator
import io.imulab.nix.oauth.client.authn.ClientSecretPostAuthenticator
import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import io.imulab.nix.oauth.reserved.AuthenticationMethod
import io.imulab.nix.oidc.client.MemoryClientStorage
import io.imulab.nix.oidc.client.authn.PrivateKeyJwtAuthenticator
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile

@Configuration
class ClientConfiguration @Autowired constructor(
    private val properties: NixProperties,
    private val jsonWebKeySetStrategy: JsonWebKeySetStrategy
) {

    @Bean @Profile("memory")
    fun memoryClientLookup() = MemoryClientStorage(mutableMapOf("foo" to Stock.clientFoo))

    @Bean
    fun clientAuthenticator(clientLookup: ClientLookup) = ClientAuthenticators(
        authenticators = listOf(
            ClientSecretBasicAuthenticator(clientLookup, BCryptPasswordEncoder()),
            ClientSecretPostAuthenticator(clientLookup, BCryptPasswordEncoder()),
            PrivateKeyJwtAuthenticator(clientLookup, jsonWebKeySetStrategy, properties)
        ),
        defaultMethod = AuthenticationMethod.clientSecretPost
    )
}