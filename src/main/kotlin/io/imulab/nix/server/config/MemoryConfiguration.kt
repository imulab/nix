package io.imulab.nix.server.config

import io.imulab.nix.oidc.client.MemoryClientStorage
import io.imulab.nix.oidc.jwk.MemoryJsonWebKeySetRepository
import io.imulab.nix.oidc.request.MemoryRequestRepository
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.server.authz.repo.MemoryOidcAuthorizeRequestRepository
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile

@Configuration
@Profile("memory")
class MemoryConfiguration {

    @Bean
    fun memoryOidcAuthorizeRequestRepository() = MemoryOidcAuthorizeRequestRepository()

    @Bean
    fun memoryJsonWebKeySetRepository() = MemoryJsonWebKeySetRepository(serverJwks = JsonWebKeySet().also { s ->
        s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
            k.keyId = "c7b318fa-4fc0-4beb-baef-91285c7ba628"
            k.use = Use.SIGNATURE
            k.algorithm = JwtSigningAlgorithm.RS256.algorithmIdentifier
        })
        s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
            k.keyId = "1eb56508-347b-4c8e-b040-5113aa18f26b"
            k.use = Use.ENCRYPTION
            k.algorithm = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
        })
    })

    @Bean
    fun memoryRequestRepository() = MemoryRequestRepository()

    @Bean
    fun memoryClientStorage() = MemoryClientStorage()   // todo: add some fake clients here
}