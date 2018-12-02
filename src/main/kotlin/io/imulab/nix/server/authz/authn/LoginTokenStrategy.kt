package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oidc.jwk.mustKeyForJweKeyManagement
import io.imulab.nix.oidc.jwk.mustKeyForSignature
import io.imulab.nix.oidc.jwk.resolvePrivateKey
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.JweContentEncodingAlgorithm
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.oidc.reserved.OidcParam
import io.imulab.nix.server.config.ServerContext
import org.jose4j.jwe.JsonWebEncryption
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
    private val serverContext: ServerContext,
    private val requestSigningAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
    private val responseEncryptionAlgorithm: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm.RSA1_5,
    private val responseEncryptionEncoding: JweContentEncodingAlgorithm = JweContentEncodingAlgorithm.A128GCM,
    private val tokenLifespan: Duration = Duration.ofMinutes(10),
    private val tokenAudience: String = serverContext.loginProviderEndpoint
) {

    fun generateLoginTokenRequest(request: OidcAuthorizeRequest): String {
        val jwk = serverContext.masterJsonWebKeySet.mustKeyForSignature(requestSigningAlgorithm)
        return JsonWebSignature().also { jws ->
            jws.payload = request.getClaims().toJson()
            jws.keyIdHeaderValue = jwk.keyId
            jws.key = jwk.resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
        }.compactSerialization
    }

    fun decodeLoginTokenResponse(token: String): JwtClaims {
        val jwt = JsonWebEncryption().also {
            it.setAlgorithmConstraints(responseEncryptionAlgorithm.whitelisted())
            it.setContentEncryptionAlgorithmConstraints(responseEncryptionEncoding.whitelisted())
            it.compactSerialization = token
            it.key = serverContext.masterJsonWebKeySet
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
            .setExpectedAudience(serverContext.authorizeEndpointUrl)
            .build()
            .processToClaims(jwt)
    }

    private fun OidcAuthorizeRequest.getClaims(): JwtClaims {
        return JwtClaims().also { c ->
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setNotBeforeMinutesInThePast(0f)
            c.setExpirationTimeMinutesInTheFuture(tokenLifespan.seconds.div(60).toFloat())
            c.issuer = serverContext.authorizeEndpointUrl
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