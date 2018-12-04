package io.imulab.nix.server.config

import io.imulab.nix.oauth.handler.OAuthAuthorizeCodeHandler
import io.imulab.nix.oauth.handler.OAuthClientCredentialsHandler
import io.imulab.nix.oauth.handler.OAuthImplicitHandler
import io.imulab.nix.oauth.handler.OAuthRefreshHandler
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.handler.helper.RefreshTokenHelper
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.storage.AuthorizeCodeRepository
import io.imulab.nix.oauth.token.storage.RefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.*
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.keys.AesKey
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
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

    /**
     * A [AccessTokenHelper] bean. This bean is the logic abstraction to generate an access token, create
     * a session for it and set it in response.
     */
    @Bean
    fun accessTokenHelper(
        nixProperties: NixProperties,
        accessTokenStrategy: AccessTokenStrategy,
        accessTokenRepository: AccessTokenRepository
    ) = AccessTokenHelper(
        oauthContext = nixProperties,
        accessTokenStrategy = accessTokenStrategy,
        accessTokenRepository = accessTokenRepository
    )

    /**
     * A [RefreshTokenHelper] bean. This bean is the logic abstraction to generate a refresh token, create
     * a session for it and set it in response.
     */
    @Bean
    fun refreshTokenHelper(
        refreshTokenStrategy: RefreshTokenStrategy,
        refreshTokenRepository: RefreshTokenRepository
    ) = RefreshTokenHelper(
        refreshTokenStrategy = refreshTokenStrategy,
        refreshTokenRepository = refreshTokenRepository
    )

    /**
     * A [OAuthAuthorizeCodeHandler] bean. This bean handles the OAuth Authorize Code Flow.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun oauthAuthorizeCodeHandler(
        authorizeCodeStrategy: AuthorizeCodeStrategy,
        authorizeCodeRepository: AuthorizeCodeRepository,
        accessTokenHelper: AccessTokenHelper,
        refreshTokenHelper: RefreshTokenHelper
    ) = OAuthAuthorizeCodeHandler(
        authorizeCodeStrategy = authorizeCodeStrategy,
        authorizeCodeRepository = authorizeCodeRepository,
        accessTokenHelper = accessTokenHelper,
        refreshTokenHelper = refreshTokenHelper
    )

    /**
     * A [OAuthImplicitHandler] bean. This bean handles the OAuth Implicit Flow.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 100)
    fun oauthImplicitHandler(
        nixProperties: NixProperties,
        accessTokenStrategy: AccessTokenStrategy,
        accessTokenRepository: AccessTokenRepository
    ) = OAuthImplicitHandler(
        oauthContext = nixProperties,
        accessTokenRepository = accessTokenRepository,
        accessTokenStrategy = accessTokenStrategy
    )

    /**
     * A [OAuthClientCredentialsHandler] bean. This bean handles the OAuth Client Credentials Flow.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 200)
    fun oauthClientCredentialsHandler(
        accessTokenHelper: AccessTokenHelper,
        refreshTokenHelper: RefreshTokenHelper
    ) = OAuthClientCredentialsHandler(
        accessTokenHelper = accessTokenHelper,
        refreshTokenHelper = refreshTokenHelper
    )

    /**
     * A [OAuthRefreshHandler] bean. This bean handles the OAuth Refresh Flow.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 300)
    fun oauthRefreshHandler(
        accessTokenHelper: AccessTokenHelper,
        refreshTokenHelper: RefreshTokenHelper,
        accessTokenRepository: AccessTokenRepository,
        refreshTokenStrategy: RefreshTokenStrategy,
        refreshTokenRepository: RefreshTokenRepository
    ) = OAuthRefreshHandler(
        accessTokenHelper = accessTokenHelper,
        refreshTokenHelper = refreshTokenHelper,
        accessTokenRepository = accessTokenRepository,
        refreshTokenRepository = refreshTokenRepository,
        refreshTokenStrategy = refreshTokenStrategy
    )
}