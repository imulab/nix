package io.imulab.nix.server.config

import io.imulab.nix.oidc.jwk.MemoryJsonWebKeySetRepository
import org.jose4j.jwk.JsonWebKeySet
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class KeyConfiguration {

    @Bean
    @Memory
    fun memoryJsonWebKeySetRepository() = MemoryJsonWebKeySetRepository(JsonWebKeySet().also { s ->
        s.addJsonWebKey(Stock.signatureKey)
        s.addJsonWebKey(Stock.encryptionKey)
    })
}