package io.imulab.nix.oidc.client

import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.Param
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.*
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.*
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.keys.AesKey
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object PrivateKeyJwtAuthenticatorSpec: Spek({

    val authenticator = PrivateKeyJwtAuthenticator(
        clientLookup = BOM.clientLookup,
        clientJwksStrategy = BOM.clientJwksStrategy,
        oauthContext = BOM.serverContext
    )

    describe("authenticate client") {

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

        it("should reject client with invalid credential") {
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
        val keySet = JsonWebKeySet().also { s ->
            s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                k.use = Use.SIGNATURE
                k.keyId = "4f043cea-f8f3-4367-a1e0-76dd402fe4f4"
            })
        }

        val clientJwksStrategy = mock<JsonWebKeySetStrategy> {
            onBlocking { resolveKeySet(any()) } doReturn keySet
        }

        val fooClient = mock<OidcClient> {
            onGeneric { id } doReturn "foo"
        }

        val clientLookup = mock<ClientLookup> {
            onBlocking { find("foo") } doReturn fooClient
        }

        val fooToken: String = JsonWebSignature().also { jws ->
            jws.key = keySet.mustKeyWithId("4f043cea-f8f3-4367-a1e0-76dd402fe4f4").resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
            jws.keyIdHeaderValue = "4f043cea-f8f3-4367-a1e0-76dd402fe4f4"
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
            jws.key = AesKey("abcdefghijklmnopqrstuvwxyz1234567890".toByteArray())
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