package io.imulab.nix.server.authz.consent

import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oidc.claim.ClaimsJsonConverter
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.mustKeyForJweKeyManagement
import io.imulab.nix.oidc.jwk.mustKeyForSignature
import io.imulab.nix.oidc.jwk.resolvePrivateKey
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.*
import io.imulab.nix.server.config.ServerContext
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration

/**
 * Strategy to process a consent token relying necessary information from [OidcAuthorizeRequest] onto the
 * internal consent provider. This strategy is responsible for generating a request token and decode the
 * response token.
 *
 * Note that right now, this strategy only supports signing the request token and encrypted response token.
 */
class ConsentTokenStrategy(
    private val oidcContext: OidcContext,
    private val requestSigningAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
    private val responseEncryptionAlgorithm: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm.RSA1_5,
    private val responseEncryptionEncoding: JweContentEncodingAlgorithm = JweContentEncodingAlgorithm.A128GCM,
    private val tokenLifespan: Duration = Duration.ofMinutes(10),
    private val tokenAudience: String,
    private val claimsJsonConverter: ClaimsJsonConverter
) {

    fun generateConsentTokenRequest(request: OidcAuthorizeRequest): String {
        val jwk = oidcContext.masterJsonWebKeySet.mustKeyForSignature(requestSigningAlgorithm)
        return JsonWebSignature().also { jws ->
            jws.payload = request.getClaims().toJson()
            jws.keyIdHeaderValue = jwk.keyId
            jws.key = jwk.resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
        }.compactSerialization
    }

    fun decodeConsentTokenResponse(token: String): JwtClaims {
        val jwt = JsonWebEncryption().also {
            it.setAlgorithmConstraints(responseEncryptionAlgorithm.whitelisted())
            it.setContentEncryptionAlgorithmConstraints(responseEncryptionEncoding.whitelisted())
            it.compactSerialization = token
            it.key = oidcContext.masterJsonWebKeySet
                .mustKeyForJweKeyManagement(responseEncryptionAlgorithm)
                .resolvePrivateKey()
        }.plaintextString

        return JwtConsumerBuilder()
            .setRequireJwtId()
            .setJwsAlgorithmConstraints(JwtSigningAlgorithm.None.whitelisted())
            .setSkipVerificationKeyResolutionOnNone()
            .setSkipSignatureVerification()
            .setDisableRequireSignature()
            .setExpectedIssuer(tokenAudience)
            .setExpectedAudience(oidcContext.authorizeEndpointUrl)
            .build()
            .processToClaims(jwt)
    }

    private fun OidcAuthorizeRequest.getClaims(): JwtClaims {
        return JwtClaims().also { c ->
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setNotBeforeMinutesInThePast(0f)
            c.setExpirationTimeMinutesInTheFuture(tokenLifespan.seconds.div(60).toFloat())
            c.issuer = oidcContext.authorizeEndpointUrl
            c.setAudience(tokenAudience, client.id)
            c.subject = session.subject

            // TODO set more client information (i.e. TOS, contact...).
            c.setStringClaim(ConsentTokenClaim.clientName, client.name)

            if (display.isNotEmpty())
                c.setStringClaim(OidcParam.display, display)
            if (uiLocales.isNotEmpty())
                c.setStringClaim(OidcParam.uiLocales, uiLocales.joinToString(separator = space))
            if (scopes.isNotEmpty())
                c.setStringClaim(Param.scope, scopes.joinToString(separator = space))
            if (claimsLocales.isNotEmpty())
                c.setStringClaim(OidcParam.claimsLocales, scopes.joinToString(separator = space))

            // TODO right now, just include claim as a JSON string, this should be fixed later.
            c.setStringClaim(OidcParam.claims, claimsJsonConverter.toJson(claims))
        }
    }
}