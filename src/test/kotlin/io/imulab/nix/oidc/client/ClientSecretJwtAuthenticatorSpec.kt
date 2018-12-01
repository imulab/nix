package io.imulab.nix.oidc.client

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.JwtSigningAlgorithm
import io.imulab.nix.oidc.OidcParam
import io.imulab.nix.oidc.OidcRequestForm
import io.imulab.nix.oidc.jwtBearerClientAssertionType
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.*
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.keys.AesKey
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientSecretJwtAuthenticatorSpec : Spek({

    val authenticator = ClientSecretJwtAuthenticator(
        clientLookup = BOM.clientLookup,
        oauthContext = BOM.serverContext
    )

    describe("authenticate client") {

        /**
         * This test works with the assumption that [OidcClient.secret] stores plain text
         * version of the secret. When this assumption changes with [ClientSecretJwtAuthenticator],
         * this test shall be updated or deleted.
         *
         * @see ClientSecretJwtAuthenticator
         */
        it("should successfully authenticate correct client") {
            val form = OidcRequestForm(
                mutableMapOf(
                    Param.clientId to listOf("foo"),
                    OidcParam.clientAssertion to listOf(BOM.fooToken),
                    OidcParam.clientAssertionType to listOf(jwtBearerClientAssertionType)
                )
            )

            assertThatCode {
                val authenticatedClient = runBlocking { authenticator.authenticate(form) }
                assertThat(authenticatedClient.id).isEqualTo("foo")
            }.doesNotThrowAnyException()
        }

        it("should reject client with invalid credentials") {
            val form = OidcRequestForm(
                mutableMapOf(
                    Param.clientId to listOf("foo"),
                    OidcParam.clientAssertion to listOf(BOM.badToken),
                    OidcParam.clientAssertionType to listOf(jwtBearerClientAssertionType)
                )
            )

            assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    runBlocking { authenticator.authenticate(form) }
                }
        }
    }
}) {

    private object BOM {

        val secret: String by lazy {
            val chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            var passWord = ""
            for (i in 0..256) {
                passWord += chars[Math.floor(Math.random() * chars.length).toInt()]
            }
            return@lazy passWord
        }

        val fooClient = mock<OidcClient> {
            onGeneric { id } doReturn "foo"
            onGeneric { secret } doReturn secret.toByteArray()
        }

        val clientLookup = mock<ClientLookup> {
            onBlocking { find("foo") } doReturn fooClient
        }

        val fooToken: String = JsonWebSignature().also { jws ->
            jws.key = AesKey(secret.toByteArray())
            jws.algorithmHeaderValue = JwtSigningAlgorithm.HS256.spec
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setExpirationTimeMinutesInTheFuture(10f)
                c.subject = "foo"
                c.issuer = "foo"
                c.setAudience("https://nix.com/oauth/token")
            }.toJson()
        }.compactSerialization

        val badToken: String = JsonWebSignature().also { jws ->
            jws.key = AesKey(secret.reversed().toByteArray())
            jws.algorithmHeaderValue = JwtSigningAlgorithm.HS256.spec
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setExpirationTimeMinutesInTheFuture(10f)
                c.subject = "foo"
                c.issuer = "foo"
                c.setAudience("https://nix.com/oauth/token")
            }.toJson()
        }.compactSerialization

        val serverContext = mock<OAuthContext> {
            onGeneric { tokenEndpointUrl } doReturn "https://nix.com/oauth/token"
        }
    }
}