package deprecated.oauth.token

import com.nhaarman.mockitokotlin2.*
import deprecated.client.OidcClient
import deprecated.client.metadata.GrantType
import deprecated.crypt.alg.EncryptionAlgorithm
import deprecated.crypt.alg.KeyManagementAlgorithm
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.oauth.request.NixTokenRequest
import deprecated.oauth.session.Session
import deprecated.oauth.token.strategy.JwxIdTokenStrategy
import deprecated.oauth.vor.JsonWebKeySetVor
import deprecated.support.findKeyForJweKeyManagement
import deprecated.support.resolvePrivateKey
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.Duration

object JwxIdTokenStrategySpec: Spek({

    val serverJwks = JsonWebKeySet().also { s ->
        s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
            k.use = Use.SIGNATURE
            k.keyId = "f1bd1b80-eaef-4606-9a95-cd5f74d771ec"
            k.algorithm = SigningAlgorithm.RS256.alg
        })
    }

    val clientJwks = JsonWebKeySet().also { s ->
        s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
            k.use = Use.ENCRYPTION
            k.keyId = "a756de8b-fb38-4d4f-8a7f-dbf2b1ae4086"
            k.algorithm = KeyManagementAlgorithm.RSA_OAEP_256.identifier
        })
    }

    val jwksVor = mock<JsonWebKeySetVor> {
        onBlocking { resolve(anyOrNull(), anyOrNull(), anyOrNull()) } doReturn clientJwks
    }

    val strategy = JwxIdTokenStrategy(
        issuer = "https://nix.com",
        idTokenLifespan = Duration.ofMinutes(30),
        jwksVor = jwksVor,
        serverJwks = serverJwks
    )

    val client = mock<OidcClient> {
        onGeneric { id } doReturn "foo"
        onGeneric { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
        onGeneric { jsonWebKeySetValue } doReturn ""
    }

    val client2 = mock<OidcClient> {
        onGeneric { id } doReturn "bar"
        onGeneric { idTokenSignedResponseAlgorithm } doReturn SigningAlgorithm.RS256
        onGeneric { idTokenEncryptedResponseAlgorithm } doReturn KeyManagementAlgorithm.RSA_OAEP_256
        onGeneric { idTokenEncryptedResponseEncoding } doReturn EncryptionAlgorithm.A256GCM
        onGeneric { jsonWebKeySetValue } doReturn ""
    }

    describe("generate signed id_token") {
        it("should return an id_token") {
            val token = GlobalScope.async {
                strategy.generateIdToken(NixTokenRequest.Companion.Builder().also { b ->
                    b.client = client
                    b.session = Session(
                        jwtClaims = JwtClaims().also { c -> c.subject = "testUser" }
                    )
                    b.addGrantType(GrantType.AuthorizationCode)
                }.build())
            }

            runBlocking {
                println(token.await().value)
                assertThat(token.await().value).isNotEmpty()
            }
        }
    }

    describe("generate encrypted id_token") {
        var encryptedIdToken = ""

        it("should return an id_token") {
            val token = GlobalScope.async {
                strategy.generateIdToken(NixTokenRequest.Companion.Builder().also { b ->
                    b.client = client2
                    b.session = Session(
                        jwtClaims = JwtClaims().also { c -> c.subject = "testUser" }
                    )
                    b.addGrantType(GrantType.AuthorizationCode)
                }.build())
            }

            runBlocking {
                encryptedIdToken = token.await().value
                assertThat(encryptedIdToken).isNotEmpty()
                println(encryptedIdToken)
            }
        }

        it("should be able to decrypt") {
            val jwk = JsonWebEncryption().also { jwe ->
                jwe.setAlgorithmConstraints(AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.WHITELIST,
                    KeyManagementAlgorithm.RSA_OAEP_256.identifier))
                jwe.setContentEncryptionAlgorithmConstraints(AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.WHITELIST, EncryptionAlgorithm.A256GCM.alg))
                jwe.compactSerialization = encryptedIdToken
                jwe.key = clientJwks.findKeyForJweKeyManagement(KeyManagementAlgorithm.RSA_OAEP_256).resolvePrivateKey()
            }.plaintextString
            println(jwk)
        }
    }
})