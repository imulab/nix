package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.discovery.OidcContext
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration

/**
 * Strategy to process a login token relying necessary information from [OidcAuthorizeRequest] onto the
 * internal login provider. This strategy is responsible for generating a request token and decode the
 * response token.
 *
 * Note that right now, this strategy only supports signing the token. Encryption support may be provided
 * in the future.
 */
class LoginTokenStrategy(
    private val oidcContext: OidcContext,
    private val signingAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
    private val tokenLifespan: Duration = Duration.ofMinutes(10),
    private val tokenAudience: String
) {

    fun generateLoginTokenRequest(request: OidcAuthorizeRequest): String {
        val jwk = oidcContext.masterJsonWebKeySet.mustKeyForSignature(signingAlgorithm)
        return JsonWebSignature().also { jws ->
            jws.payload = request.getClaims().toJson()
            jws.keyIdHeaderValue = jwk.keyId
            jws.key = jwk.resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
        }.compactSerialization
    }

    fun decodeLoginTokenResponse(token: String): JwtClaims {
        return JwtConsumerBuilder()
            .setRequireJwtId()
            .setJwsAlgorithmConstraints(signingAlgorithm.whitelisted())
            .setVerificationKeyResolver(
                JwtVerificationKeyResolver(oidcContext.masterJsonWebKeySet, signingAlgorithm)
            )
            .setExpectedIssuer(tokenAudience)
            .setExpectedAudience(oidcContext.issuerUrl)
            .build()
            .processToClaims(token)
    }

    private fun OidcAuthorizeRequest.getClaims(): JwtClaims {
        return JwtClaims().also { c ->
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setNotBeforeMinutesInThePast(0f)
            c.setExpirationTimeMinutesInTheFuture(tokenLifespan.seconds.div(60).toFloat())
            c.issuer = oidcContext.issuer
            c.setAudience(tokenAudience, client.id)
            c.subject = "login"

            if (maxAge > 0)
                c.setStringClaim(OidcParam.maxAge, maxAge.toString())
            if (display.isNotEmpty())
                c.setStringClaim(OidcParam.display, display)
            if (uiLocales.isNotEmpty())
                c.setStringClaim(OidcParam.uiLocales, uiLocales.joinToString(separator = space))
            if (loginHint.isNotEmpty())
                c.setStringClaim(OidcParam.loginHint, loginHint)
            if (acrValues.isNotEmpty())
                c.setStringClaim(OidcParam.acrValues, acrValues.joinToString(separator = space))
        }
    }
}