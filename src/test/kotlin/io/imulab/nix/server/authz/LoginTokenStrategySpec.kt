package io.imulab.nix.server.authz

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oidc.jwk.loginHint
import io.imulab.nix.oidc.jwk.maxAge
import io.imulab.nix.oauth.token.mustKeyForJweKeyManagement
import io.imulab.nix.oauth.token.resolvePublicKey
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.JweContentEncodingAlgorithm
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.server.authz.LoginTokenStrategySpec.generateResponseToken
import io.imulab.nix.server.authz.authn.LoginTokenStrategy
import io.imulab.nix.server.config.ServerContext
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object LoginTokenStrategySpec : Spek({

    val strategy = LoginTokenStrategy(
        oidcContext = BOM.oidcContext,
        tokenAudience = BOM.loginProvider
    )

    describe("Issue login token") {

        var token = ""
        val request = OidcAuthorizeRequest.Builder().also { b ->
            b.client = mock()
            b.maxAge = 3600
            b.loginHint = "email"
        }.build()

        it("should generate login token") {
            token = strategy.generateLoginTokenRequest(request)
            assertThat(token).isNotEmpty()
        }

        it("login provider should be able to decode token") {
            val claims = JwtConsumerBuilder().also { b ->
                b.setRequireJwtId()
                b.setVerificationKey(BOM.jwks.findJsonWebKey(null, null, Use.SIGNATURE, null).resolvePublicKey())
                b.setExpectedIssuer(BOM.oidcContext.authorizeEndpointUrl)
                b.setExpectedAudience(BOM.loginProvider)
            }.build().processToClaims(token)
            assertThat(claims.maxAge()).isEqualTo(3600)
            assertThat(claims.loginHint()).isEqualTo("email")
        }
    }

    describe("Decode response token") {
        val loginToken = generateResponseToken()
        var claims = JwtClaims()

        it("strategy should be able to process token") {
            claims = strategy.decodeLoginTokenResponse(loginToken)
        }

        it("idTokenClaims should reflect authentication status") {
            assertThat(claims.subject).isEqualTo("foo@bar.com")
        }
    }

}) {
    private object BOM {

        const val loginProvider = "https://login.nix.com"

        val jwks = JsonWebKeySet().also { jwks ->
            jwks.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                k.keyId = "3a400f6f-d66e-4734-b272-c597d147e9ad"
                k.use = Use.SIGNATURE
                k.algorithm = JwtSigningAlgorithm.RS256.algorithmIdentifier
            })
            jwks.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                k.keyId = "a363e5aa-d29e-4ea9-a8b0-f7149ddc0f1f"
                k.use = Use.ENCRYPTION
                k.algorithm = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
            })
        }

        val oidcContext = mock<ServerContext> {
            onGeneric { authorizeEndpointUrl } doReturn "https://nix.com/oauth/authorize"
            onGeneric { masterJsonWebKeySet } doReturn jwks
        }
    }

    fun generateResponseToken(): String {
        val jwt = JsonWebSignature().also { jws ->
            jws.setAlgorithmConstraints(JwtSigningAlgorithm.None.whitelisted())
            jws.algorithmHeaderValue = JwtSigningAlgorithm.None.algorithmIdentifier
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setExpirationTimeMinutesInTheFuture(10f)
                c.issuer = BOM.loginProvider
                c.setAudience(BOM.oidcContext.authorizeEndpointUrl)
                c.subject = "foo@bar.com"
            }.toJson()
        }.compactSerialization

        return JsonWebEncryption().also { jwe ->
            jwe.contentTypeHeaderValue = "JWT"
            jwe.setPlaintext(jwt)
            jwe.encryptionMethodHeaderParameter = JweContentEncodingAlgorithm.A128GCM.algorithmIdentifier
            jwe.algorithmHeaderValue = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
            jwe.key = BOM.jwks.mustKeyForJweKeyManagement(JweKeyManagementAlgorithm.RSA1_5).resolvePublicKey()
        }.compactSerialization
    }
}