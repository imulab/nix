package io.imulab.nix.server.config

import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import io.imulab.nix.oauth.reserved.ClientType
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.reserved.StandardScope
import io.imulab.nix.oauth.token.storage.MemoryAccessTokenRepository
import io.imulab.nix.oauth.token.storage.MemoryAuthorizeCodeRepository
import io.imulab.nix.oauth.token.storage.MemoryRefreshTokenRepository
import io.imulab.nix.oidc.client.MemoryClientStorage
import io.imulab.nix.oidc.jwk.MemoryJsonWebKeySetRepository
import io.imulab.nix.oidc.request.MemoryOidcSessionRepository
import io.imulab.nix.oidc.request.MemoryRequestRepository
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.server.authz.repo.MemoryOidcAuthorizeRequestRepository
import io.imulab.nix.server.client.NixClient
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.session.ReactiveMapSessionRepository
import org.springframework.session.config.annotation.web.server.EnableSpringWebSession
import java.util.concurrent.ConcurrentHashMap

/**
 * This class configures all in memory repositories.
 */
@Configuration
@EnableSpringWebSession
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
    fun memoryClientStorage() = MemoryClientStorage(database = mutableMapOf(
        "foo" to NixClient.Builder().also { b ->
            b.id = "foo"
            b.name = "Foo"
            b.type = ClientType.confidential
            b.secret = BCryptPasswordEncoder().encode("s3cret").toByteArray()
            b.responseTypes = mutableSetOf(
                ResponseType.code,
                ResponseType.token,
                io.imulab.nix.oidc.reserved.ResponseType.idToken
            )
            b.grantTypes = mutableSetOf(
                GrantType.authorizationCode,
                GrantType.clientCredentials,
                GrantType.implicit,
                GrantType.refreshToken
            )
            b.redirectUris = mutableSetOf(
                "http://localhost:8888/callback"
            )
            b.scopes = mutableSetOf(
                "foo",
                "bar",
                StandardScope.offlineAccess,
                io.imulab.nix.oidc.reserved.StandardScope.openid
            )
        }.build()
    ))

    @Bean
    fun webSessionRepository() = ReactiveMapSessionRepository(ConcurrentHashMap())

    @Bean
    fun authorizeCodeRepository() = MemoryAuthorizeCodeRepository()

    @Bean
    fun accessTokenRepository() = MemoryAccessTokenRepository()

    @Bean
    fun refreshTokenRepository() = MemoryRefreshTokenRepository()

    @Bean
    fun oidcSessionRepository() = MemoryOidcSessionRepository()
}