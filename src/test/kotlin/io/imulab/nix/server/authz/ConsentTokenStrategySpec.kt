package io.imulab.nix.server.authz

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.mustKeyForJweKeyManagement
import io.imulab.nix.oidc.jwk.resolvePublicKey
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.ConsentTokenClaim
import io.imulab.nix.oidc.reserved.JweContentEncodingAlgorithm
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.server.authz.ConsentTokenStrategySpec.generateResponseToken
import io.imulab.nix.server.authz.consent.ConsentTokenStrategy
import io.imulab.nix.server.oidc.GsonClaimsConverter
import org.assertj.core.api.Assertions
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object ConsentTokenStrategySpec : Spek({

    val strategy = ConsentTokenStrategy(
        oidcContext = BOM.oidcContext,
        tokenAudience = BOM.consentProvider,
        claimsJsonConverter = GsonClaimsConverter
    )

    describe("Issue consent token") {

        var token = ""
        val request = OidcAuthorizeRequest.Builder().also { b ->
            b.client = BOM.client
            b.scopes = mutableSetOf("foo", "bar")
            b.maxAge = 3600
            b.session.subject = "foo@bar.com"
            b.session.authTime = LocalDateTime.now().minusSeconds(5)
        }.build()

        it("should generate token") {
            token = strategy.generateConsentTokenRequest(request)
        }

        it("consent provider should be able to decode token") {
            val claims = JwtConsumerBuilder().also { b ->
                b.setRequireJwtId()
                b.setVerificationKey(BOM.jwks.findJsonWebKey(null, null, Use.SIGNATURE, null).resolvePublicKey())
                b.setExpectedIssuer(BOM.oidcContext.authorizeEndpointUrl)
                b.setExpectedAudience(BOM.consentProvider)
            }.build().processToClaims(token)
            Assertions.assertThat(claims.subject).isEqualTo("foo@bar.com")
            Assertions.assertThat(claims.getStringClaimValue(ConsentTokenClaim.clientName)).isEqualTo(BOM.client.name)
            Assertions.assertThat(claims.getStringClaimValue(Param.scope)).contains("foo", "bar")
        }
    }

    describe("Decode response token") {
        val consentToken = generateResponseToken()
        var claims = JwtClaims()

        it("strategy should be able to process token") {
            claims = strategy.decodeConsentTokenResponse(consentToken)
        }

        it("claims should reflect authentication status") {
            Assertions.assertThat(claims.subject).isEqualTo("foo@bar.com")
        }
    }
}) {

    private object BOM {
        const val consentProvider = "https://login.nix.com"

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

        val oidcContext = mock<OidcContext> {
            onGeneric { authorizeEndpointUrl } doReturn "https://nix.com/oauth/authorize"
            onGeneric { masterJsonWebKeySet } doReturn jwks
        }

        val client = mock<OidcClient> {
            onGeneric { id } doReturn "777aaf77-50be-44bc-afcb-853192c2918b"
            onGeneric { name } doReturn "Test Client"
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
                c.issuer = BOM.consentProvider
                c.setAudience(BOM.oidcContext.authorizeEndpointUrl)
                c.subject = "foo@bar.com"
                c.setClaim(ConsentTokenClaim.scope, "foo bar")
                c.setClaim(ConsentTokenClaim.remember, 1018080)
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