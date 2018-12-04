package io.imulab.nix.oauth.handler

import com.nhaarman.mockitokotlin2.argThat
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.UnsupportedGrantType
import io.imulab.nix.oauth.handler.OAuthImplicitHandlerSpec.validAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.token.storage.MemoryAccessTokenRepository
import io.imulab.nix.oauth.token.strategy.JwtAccessTokenStrategy
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.then
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.spekframework.spek2.Spek
import java.time.Duration

object OAuthImplicitHandlerSpec : Spek({

    given("a configured handler") {
        val given = Given()
        val handler = given.handler

        `when`("a valid request is presented") {
            val request = validAuthorizeRequest()
            val response = AuthorizeEndpointResponse()
            runBlocking { handler.handleAuthorizeRequest(request, response) }

            then("response_type=token should have been handled") {
                assertThat(response.handledResponseTypes).contains(ResponseType.token)
            }

            then("an access token should have been issued in response") {
                assertThat(response.accessToken).isNotEmpty()
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

        `when`("a request was made without response_type=token") {
            val request = OAuthAuthorizeRequest.Builder().also { b ->
                b.client = mock()
                b.redirectUri = "https://test.com/callback"
                b.responseTypes = mutableSetOf(ResponseType.code)
            }.build()
            val response = AuthorizeEndpointResponse()
            runBlocking { handler.handleAuthorizeRequest(request, response) }

            then("response_type=token should not have been handled") {
                assertThat(response.handledResponseTypes).doesNotContain(ResponseType.token)
            }
        }
    }

}) {
    class Given {
        private val oauthContext = mock<OAuthContext> {
            onGeneric { accessTokenLifespan } doReturn Duration.ofMinutes(60)
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

        val handler = OAuthImplicitHandler(
            oauthContext = oauthContext,
            accessTokenStrategy = accessTokenStrategy,
            accessTokenRepository = accessTokenRepository
        )
    }

    fun validAuthorizeRequest() : OAuthAuthorizeRequest {
        val client = mock<OAuthClient> {
            onGeneric { id } doReturn "foo"
            onGeneric { mustGrantType(argThat { this != GrantType.implicit }) } doAnswer { iom ->
                throw UnsupportedGrantType.unsupported(iom.arguments[0] as String)
            }
        }

        return OAuthAuthorizeRequest.Builder().also { b ->
            b.client = client
            b.redirectUri = "https://test.com/callback"
            b.responseTypes = mutableSetOf(ResponseType.token)
            b.scopes = mutableSetOf("foo", "bar")
            b.state = "12345678"
        }.build().also { r ->
            r.session.subject = "tester"
            r.session.grantedScopes.add("foo")
        }
    }
}