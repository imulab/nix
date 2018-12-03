package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.token.mustKeyForSignature
import io.imulab.nix.oauth.token.resolvePrivateKey
import io.imulab.nix.oauth.token.resolvePublicKey
import io.imulab.nix.oauth.token.setScope
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.ReservedClaimNames
import org.jose4j.jwt.consumer.ErrorCodes
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.lang.Exception

class JwtAccessTokenStrategy(
    private val oauthContext: OAuthContext,
    private val signingAlgorithm: JwtSigningAlgorithm,
    serverJwks: JsonWebKeySet
) : AccessTokenStrategy {

    private val jwk = serverJwks.mustKeyForSignature(signingAlgorithm)
    private val reservedClaims = setOf(
        ReservedClaimNames.JWT_ID,
        ReservedClaimNames.ISSUED_AT,
        ReservedClaimNames.NOT_BEFORE,
        ReservedClaimNames.EXPIRATION_TIME,
        ReservedClaimNames.ISSUER,
        ReservedClaimNames.SUBJECT,
        ReservedClaimNames.AUDIENCE,
        Param.scope
    )

    override fun computeIdentifier(token: String): String {
        return try {
            JwtConsumerBuilder()
                .setSkipAllValidators()
                .setRequireJwtId()
                .build()
                .processToClaims(token).jwtId
        } catch (e: Exception) {
            throw InvalidGrant.invalid()
        }
    }

    override suspend fun generateToken(request: OAuthRequest): String {
        return JsonWebSignature().also { jws ->
            if (jwk.keyId != null)
                jws.keyIdHeaderValue = jwk.keyId
            jws.algorithmHeaderValue = signingAlgorithm.algorithmIdentifier
            jws.key = jwk.resolvePrivateKey()
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setNotBeforeMinutesInThePast(0f)
                c.setExpirationTimeMinutesInTheFuture(oauthContext.accessTokenLifespan.toMinutes().toFloat())
                c.issuer = oauthContext.issuerUrl
                c.subject = request.session.subject
                c.setAudience(request.client.id)
                c.setScope(request.session.grantedScopes)
                request.session.accessTokenClaims
                    .filterKeys { !reservedClaims.contains(it) }
                    .forEach { t, u -> c.setClaim(t, u) }
            }.toJson()
        }.compactSerialization
    }

    override suspend fun verifyToken(token: String, request: OAuthRequest) {
        try {
            JwtConsumerBuilder()
                .setRequireJwtId()
                .setVerificationKey(jwk.resolvePublicKey())
                .setExpectedIssuer(oauthContext.issuerUrl)
                .setSkipDefaultAudienceValidation()
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .build()
                .process(token)
        } catch (e: InvalidJwtException) {
            when {
                e.errorDetails.any { it.errorCode == ErrorCodes.EXPIRED } ->
                    throw InvalidGrant.expired()
                else -> throw InvalidGrant.invalid()
            }
        }
    }
}