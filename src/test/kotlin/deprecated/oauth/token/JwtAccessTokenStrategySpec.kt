package deprecated.oauth.token

import com.nhaarman.mockitokotlin2.mock
import deprecated.client.Client
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.oauth.request.NixTokenRequest
import deprecated.oauth.session.Session
import deprecated.oauth.token.strategy.JwtAccessTokenStrategy
import deprecated.support.findKeyForSignature
import deprecated.support.getScopes
import deprecated.support.maybe
import deprecated.support.resolvePublicKey
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwk.EcJwkGenerator
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.EllipticCurves
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object JwtAccessTokenStrategySpec: Spek({

    val signAlg = SigningAlgorithm.ES256

    val keySet = JsonWebKeySet().also { s ->
        s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also {
            it.use = Use.SIGNATURE
            it.keyId = "0354A698-82C5-4B98-A13C-AB608B219897"
        })
        s.addJsonWebKey(EcJwkGenerator.generateJwk(EllipticCurves.P256).also {
            it.use = Use.SIGNATURE
            it.keyId = "ADF472C0-308E-4EE6-84EE-C3B11545AC7D"
        })
    }

    val strategy = JwtAccessTokenStrategy(
        issuer = "https://test.nix.com",
        signingAlgorithm = signAlg,
        serverJwks = keySet
    )

    describe("generate new token") {

        var rawToken = ""

        it("should generate new token") {
            val token = strategy.generateToken(NixTokenRequest.Companion.Builder().also { b ->
                b.client = Client(id = "848F34F7-76FB-4074-AEA4-56CD461BAF58")
                b.grantedScopes = mutableSetOf("foo", "bar")
                b.session = Session(
                    expiry = mutableMapOf(
                        TokenType.AccessToken to LocalDateTime.now().plusHours(1)
                    ),
                    subject = "user/D363D388-E8F4-4913-B4DC-9731DB78A433",
                    jwtClaims = JwtClaims().also { c ->
                        c.issuer = "this-should-be-ignored"
                        c.subject = "user/backup-value-so-should-be-ignored"
                        c.setClaim("X-custom-claim", "this-should-be-included")
                    }
                )
            }.build())
            rawToken = token.toString()
            println(rawToken)
        }

        it("should pass verification") {
            val verified = strategy.verifyToken(mock(),
                JwtToken(TokenType.AccessToken, rawToken)
            )
            assertThat(verified.value).isEqualTo(rawToken)

            val decoded = JwtConsumerBuilder().also {
                it.setSkipAllValidators()
                it.setVerificationKey(keySet.findKeyForSignature(signAlg).resolvePublicKey())
            }.build().processToClaims(verified.value)

            assertThat(decoded.subject).isEqualTo("user/D363D388-E8F4-4913-B4DC-9731DB78A433")
            assertThat(decoded.issuer).isEqualTo("https://test.nix.com")
            assertThat(decoded.audience[0]).isEqualTo("848F34F7-76FB-4074-AEA4-56CD461BAF58")
            assertThat(decoded.getScopes()).contains("foo", "bar")
            assertThat(decoded.maybe("X-custom-claim")).isEqualTo("this-should-be-included")
        }
    }
})