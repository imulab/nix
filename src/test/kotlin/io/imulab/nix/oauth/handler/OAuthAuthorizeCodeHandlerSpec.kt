package io.imulab.nix.oauth.handler

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.handler.OAuthAuthorizeCodeHandlerSpec.validAccessRequest
import io.imulab.nix.oauth.handler.OAuthAuthorizeCodeHandlerSpec.validAuthorizeRequest
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.handler.helper.RefreshTokenHelper
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.reserved.StandardScope
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.MemoryAccessTokenRepository
import io.imulab.nix.oauth.token.storage.MemoryAuthorizeCodeRepository
import io.imulab.nix.oauth.token.storage.MemoryRefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.HmacSha2AuthorizeCodeStrategy
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

object OAuthAuthorizeCodeHandlerSpec : Spek({

    given("a configured handler") {
        val given = Given()
        val handler = given.handler

        `when`("a valid request is submitted") {
            val request = validAuthorizeRequest()
            val response = AuthorizeEndpointResponse()
            runBlocking { handler.handleAuthorizeRequest(request, response) }

            then("response_type=code should have been handled") {
                assertThat(response.handledResponseTypes).contains(ResponseType.code)
            }

            then("authorization code should be generated in response") {
                assertThat(response.code).isNotEmpty()
            }

            then("granted scope should be presented in response") {
                assertThat(response.scope).contains("foo")
                assertThat(response.scope).doesNotContain("bar")
            }

            then("state should be passed on in response") {
                assertThat(response.state).isEqualTo(request.state)
            }

            then("authorization session should be created") {
                assertThat(
                    runBlocking { given.authorizeCodeRepository.getAuthorizeCodeSession(response.code) }
                ).isNotNull
            }
        }

        `when`("a request is submitted without response_type=code") {
            val request = OAuthAuthorizeRequest.Builder().also { b ->
                b.responseTypes = mutableSetOf(ResponseType.token)
                b.client = mock()
                b.redirectUri = "https://test.com/callback"
            }.build()
            val response = AuthorizeEndpointResponse()
            runBlocking { handler.handleAuthorizeRequest(request, response) }

            then("response_type=code should not have been handled") {
                assertThat(response.handledResponseTypes).doesNotContain(ResponseType.code)
            }

            then("no authorization code should have been issued in response") {
                assertThat(response.code).isEmpty()
            }
        }
    }

    given("""
        a configured handler, and
        a previously existing authorization code session
    """.trimIndent()) {
        val given = Given()
        val handler = given.handler
        val authorizeCode = runBlocking {
            AuthorizeEndpointResponse().also {
                handler.handleAuthorizeRequest(validAuthorizeRequest(), it)
            }.code
        }.also {
            assertThat(it).isNotEmpty()
        }

        `when`("a valid request is submitted") {
            val request = validAccessRequest(authorizeCode)
            val response = TokenEndpointResponse()
            runBlocking {
                handler.updateSession(request)
                handler.handleAccessRequest(request, response)
            }

            then("an access token should have been issued in response") {
                assertThat(response.accessToken).isNotEmpty()
                println(response.data)
            }

            then("token type should have been set in response") {
                assertThat(response.tokenType).isEqualTo("bearer")
            }

            then("expiration ttl should have been set in response") {
                assertThat(response.expiresIn).isGreaterThan(0)
            }

            then("granted scopes should have been set in response") {
                assertThat(response.scope).contains("foo")
                assertThat(response.scope).doesNotContain("bar")
            }

            then("an access token session should have been created") {
                assertThat(runBlocking { given.accessTokenRepository.getAccessTokenSession(response.accessToken) })
                    .isNotNull
            }
        }
    }

    given("""
        a configured handler, and
        a previously existing authorization code session, and
        scope=offline is granted
    """.trimIndent()) {
        val given = Given()
        val handler = given.handler
        val authorizeCode = runBlocking {
            AuthorizeEndpointResponse().also {
                handler.handleAuthorizeRequest(
                    validAuthorizeRequest().also { r -> r.session.grantedScopes.add(StandardScope.offlineAccess) },
                    it
                )
            }.code
        }.also {
            assertThat(it).isNotEmpty()
        }

        `when`("a valid request is submitted") {
            val request = validAccessRequest(authorizeCode)
            val response = TokenEndpointResponse()
            runBlocking {
                handler.updateSession(request)
                handler.handleAccessRequest(request, response)
            }

            then("an refresh token should have been issued in response") {
                assertThat(response.refreshToken).isNotEmpty()
                println(response.data)
            }
        }
    }
}) {

    open class Given {
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

        private val authorizeCodeStrategy = HmacSha2AuthorizeCodeStrategy(
            key = AesKey("182efc6d4c6e4cf6a78ce6af64dfa6b5".toByteArray()),
            codeLength = 16,
            signingAlgorithm = JwtSigningAlgorithm.HS256
        )

        val authorizeCodeRepository = MemoryAuthorizeCodeRepository()

        private val accessTokenStrategy = JwtAccessTokenStrategy(
            oauthContext = oauthContext,
            signingAlgorithm = JwtSigningAlgorithm.RS256,
            serverJwks = serverJwks
        )

        val accessTokenRepository = MemoryAccessTokenRepository()

        private val refreshTokenStrategy = HmacSha2RefreshTokenStrategy(
            key = AesKey("2fb9a6e7a6014e609cc7a42812dae6c7".toByteArray()),
            tokenLength = 16,
            signingAlgorithm = JwtSigningAlgorithm.HS256
        )

        private val refreshTokenRepository = MemoryRefreshTokenRepository()

        val handler = OAuthAuthorizeCodeHandler(
            authorizeCodeStrategy = authorizeCodeStrategy,
            authorizeCodeRepository = authorizeCodeRepository,
            accessTokenHelper = AccessTokenHelper(
                oauthContext = oauthContext,
                accessTokenRepository = accessTokenRepository,
                accessTokenStrategy = accessTokenStrategy
            ),
            refreshTokenHelper = RefreshTokenHelper(
                refreshTokenStrategy = refreshTokenStrategy,
                refreshTokenRepository = refreshTokenRepository
            )
        )
    }

    fun validAuthorizeRequest(): OAuthAuthorizeRequest {
        val client = mock<OAuthClient> {
            onGeneric { id } doReturn "foo"
        }
        return OAuthAuthorizeRequest.Builder().also { b ->
            b.client = client
            b.redirectUri = "https://test.com/callback"
            b.responseTypes = mutableSetOf(ResponseType.code)
            b.scopes = mutableSetOf("foo", "bar")
            b.state = "12345678"
        }.build().also { r ->
            r.session.subject = "tester"
            r.session.grantedScopes.add("foo")
        }
    }

    fun validAccessRequest(authorizeCode: String): OAuthAccessRequest {
        val client = mock<OAuthClient> {
            onGeneric { id } doReturn "foo"
        }
        return OAuthAccessRequest.Builder().also { b ->
            b.client = client
            b.code = authorizeCode
            b.grantTypes = mutableSetOf(GrantType.authorizationCode)
            b.redirectUri = "https://test.com/callback"
        }.build()
    }
}