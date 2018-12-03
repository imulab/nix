package io.imulab.nix.server.config

import io.imulab.nix.oauth.token.strategy.HmacSha2AuthorizeCodeStrategy
import io.imulab.nix.oauth.token.strategy.HmacSha2RefreshTokenStrategy
import io.imulab.nix.oauth.token.strategy.JwtAccessTokenStrategy
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.keys.AesKey
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.nio.charset.StandardCharsets

/**
 * This class configures OAuth related components (minus state management).
 */
@Configuration
class OAuthConfiguration {

    /**
     * A [HmacSha2AuthorizeCodeStrategy] bean. This bean is responsible for generating and verifying
     * an authorization code.
     */
    @Bean
    fun authorizeCodeStrategy(nixProperties: NixProperties) = HmacSha2AuthorizeCodeStrategy(
        key = AesKey(nixProperties.authorizeCode.key.toByteArray(StandardCharsets.UTF_8)),
        signingAlgorithm = JwtSigningAlgorithm.HS512,
        codeLength = 16
    )

    /**
     * A [JwtAccessTokenStrategy] bean. This bean is responsible for generating and verifying
     * an access token.
     */
    @Bean
    fun accessTokenStrategy(nixProperties: NixProperties) = JwtAccessTokenStrategy(
        oauthContext = nixProperties,
        serverJwks = nixProperties.masterJsonWebKeySet,
        signingAlgorithm = JwtSigningAlgorithm.RS256
    )

    /**
     * A [HmacSha2RefreshTokenStrategy] bean. This bean is responsible for generating and verifying
     * a refresh token.
     */
    @Bean
    fun refreshTokenStrategy(nixProperties: NixProperties) = HmacSha2RefreshTokenStrategy(
        key = AesKey(nixProperties.refreshToken.key.toByteArray(StandardCharsets.UTF_8)),
        signingAlgorithm = JwtSigningAlgorithm.HS512,
        tokenLength = 32
    )
}