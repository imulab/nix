package io.imulab.nix.oauth.handler

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.handler.OAuthRefreshHandlerSpec.validAccessRequest
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.handler.helper.RefreshTokenHelper
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.MemoryAccessTokenRepository
import io.imulab.nix.oauth.token.storage.MemoryRefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.HmacSha2RefreshTokenStrategy
import io.imulab.nix.oauth.token.strategy.JwtAccessTokenStrategy
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.then
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.keys.AesKey
import org.spekframework.spek2.Spek
import java.time.Duration

object OAuthRefreshHandlerSpec : Spek({

    given("""
        a configured handler, and
        a previously existing refresh token
    """.trimIndent()) {
        val given = Given()
        val refreshToken = given.originalRefreshToken
        val handler = given.handler

        `when`("a valid access request is made") {
            val request = validAccessRequest(refreshToken)
            val response = TokenEndpointResponse()
            runBlocking {
                handler.updateSession(request)
                handler.handleAccessRequest(request, response)
            }

            then("a new access token should be issued") {
                assertThat(response.accessToken).isNotEmpty()
            }

            then("a new refresh token should be issued") {
                assertThat(response.refreshToken).isNotEmpty()
                assertThat(response.refreshToken).isNotEqualTo(refreshToken)
            }

            then("granted scopes should be the same as before") {
                assertThat(response.scope).contains("foo", "offline_access")
                assertThat(response.scope).doesNotContain("bar")
            }
        }
    }

}) {
    class Given {
        private val oauthContext = mock<OAuthContext> {
            onGeneric { accessTokenLifespan } doReturn Duration.ofMinutes(10)
        }

        private val serverJwks = JsonWebKeySet().also { s ->
            s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                k.use = Use.SIGNATURE
                k.keyId = "20474f4a-f49d-4e29-bc65-312eed593215"
                k.algorithm = JwtSigningAlgorithm.RS256.algorithmIdentifier
            })
        }

        private val accessTokenStrategy = JwtAccessTokenStrategy(
            oauthContext = oauthContext,
            signingAlgorithm = JwtSigningAlgorithm.RS256,
            serverJwks = serverJwks
        )

        val accessTokenRepository = MemoryAccessTokenRepository()

        val originalRefreshToken: String by lazy {
            var refreshToken = ""
            val client = mock<OAuthClient> {
                onGeneric { id } doReturn "foo"
            }
            val req = OAuthAuthorizeRequest.Builder().also { b ->
                b.client = client
                b.redirectUri = "https://test.com/callback"
                b.responseTypes = mutableSetOf(ResponseType.token)
                b.scopes = mutableSetOf("foo", "bar", "offline_access")
                b.state = "12345678"
            }.build().also { r ->
                r.session.subject = "tester"
                r.session.grantedScopes.addAll(listOf("foo", "offline_access"))
            }
            runBlocking {
                refreshToken = refreshTokenStrategy.generateToken(req)
                refreshTokenRepository.createRefreshTokenSession(refreshToken, req)
            }
            return@lazy refreshToken
        }

        private val refreshTokenStrategy = HmacSha2RefreshTokenStrategy(
            key = AesKey("2fb9a6e7a6014e609cc7a42812dae6c7".toByteArray()),
            tokenLength = 16,
            signingAlgorithm = JwtSigningAlgorithm.HS256
        )

        private val refreshTokenRepository = MemoryRefreshTokenRepository()

        val handler = OAuthRefreshHandler(
            refreshTokenStrategy = refreshTokenStrategy,
            refreshTokenRepository = refreshTokenRepository,
            accessTokenRepository = accessTokenRepository,
            refreshTokenHelper = RefreshTokenHelper(
                refreshTokenStrategy = refreshTokenStrategy,
                refreshTokenRepository = refreshTokenRepository
            ),
            accessTokenHelper = AccessTokenHelper(
                oauthContext = oauthContext,
                accessTokenRepository = accessTokenRepository,
                accessTokenStrategy = accessTokenStrategy
            )
        )
    }

    fun validAccessRequest(refreshToken: String): OAuthAccessRequest {
        val client = mock<OAuthClient> {
            onGeneric { id } doReturn "foo"
        }
        return OAuthAccessRequest.Builder().also { b ->
            b.client = client
            b.refreshToken = refreshToken
            b.grantTypes = mutableSetOf(GrantType.refreshToken)
            b.redirectUri = "https://test.com/callback"
        }.build()
    }
}