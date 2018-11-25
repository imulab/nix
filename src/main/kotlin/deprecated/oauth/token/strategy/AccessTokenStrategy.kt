package deprecated.oauth.token.strategy

import deprecated.constant.Error
import deprecated.constant.Misc.DOT
import deprecated.constant.Param
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.crypt.sign.JwtVerificationKeyResolver
import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.session.JwtSession
import deprecated.oauth.token.JwtToken
import deprecated.oauth.token.Token
import deprecated.oauth.token.TokenType
import deprecated.support.*
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.ReservedClaimNames
import org.jose4j.jwt.consumer.ErrorCodes
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

interface AccessTokenStrategy {

    /**
     * Parses the [raw] representation of access token.
     */
    fun fromRaw(raw: String): Token

    /**
     * Create a new access token, with signature computed.
     */
    fun generateToken(request: OAuthRequest): Token

    /**
     * Validate the provided [token].
     */
    fun verifyToken(request: OAuthRequest, token: Token): Token
}

class JwtAccessTokenStrategy(
    private val issuer: String,
    private val signingAlgorithm: SigningAlgorithm,
    private val serverJwks: JsonWebKeySet
): AccessTokenStrategy {

    override fun fromRaw(raw: String): Token {
        requireThreeParts(raw)
        return JwtToken(TokenType.AccessToken, raw)
    }

    override fun generateToken(request: OAuthRequest): Token {
        val session = request.session.assertType<JwtSession>()

        require(session.jwtClaims.claimsMap.isNotEmpty()) {
            "jwt session claims map must not be empty, did upstream overlook this?"
        }
        requireNotNull(session.expiry[TokenType.AccessToken]) {
            "access token expiry must be set in jwt session, did upstream overlook this?"
        }

        val jwk = serverJwks.findKeyForSignature(signingAlgorithm)
        val jwt = JsonWebSignature().also { jws ->
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setNotBeforeMinutesInThePast(0f)
                c.setExpirationTimeMinutesInTheFuture(
                    LocalDateTime.now().until(
                        session.expiry[TokenType.AccessToken]!!,
                        ChronoUnit.MINUTES
                    ).toFloat()
                )
                c.issuer = issuer
                c.subject = session.subject
                    .switchOnEmpty(session.jwtClaims.maybe(ReservedClaimNames.SUBJECT))
                c.setAudience(request.client.id)
                c.setScopes(request.grantedScopes.toList())
                session.jwtClaims.getClaimsMap(setOf(
                    ReservedClaimNames.JWT_ID,
                    ReservedClaimNames.ISSUED_AT,
                    ReservedClaimNames.NOT_BEFORE,
                    ReservedClaimNames.EXPIRATION_TIME,
                    ReservedClaimNames.ISSUER,
                    ReservedClaimNames.SUBJECT,
                    ReservedClaimNames.AUDIENCE,
                    Param.SCOPE
                )).forEach { t, u ->
                    c.setClaim(t, u)
                }
            }.toJson()
            session.jwtHeaders.forEach { t, u -> jws.setHeader(t, u) }
            jws.keyIdHeaderValue = jwk.keyId
            jws.algorithmHeaderValue = signingAlgorithm.alg
            jws.key = jwk.resolvePrivateKey()
        }.compactSerialization

        return JwtToken(TokenType.AccessToken, jwt)
    }

    override fun verifyToken(request: OAuthRequest, token: Token): Token {
        try {
            JwtConsumerBuilder()
                .setRequireJwtId()
                .setVerificationKeyResolver(
                    JwtVerificationKeyResolver(
                        serverJwks,
                        signingAlgorithm
                    )
                )
                .setExpectedIssuer(issuer)
                .setSkipDefaultAudienceValidation()
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .build()
                .process(token.value)
        } catch (e: InvalidJwtException) {
            when {
                e.errorDetails.any { it.errorCode == ErrorCodes.EXPIRED } ->
                    throw Error.AccessToken.expired()
                e.errorDetails.any { it.errorCode == ErrorCodes.SIGNATURE_INVALID } ->
                    throw Error.AccessToken.badSignature()
                else -> throw Error.AccessToken.verifyFailed(e)
            }
        }

        return JwtToken(TokenType.AccessToken, token.value)
    }

    private fun requireThreeParts(raw: String): List<String> {
        val parts = raw.split(DOT)
        if (parts.size != 3)
            throw Error.AccessToken.badFormat()
        return parts
    }
}