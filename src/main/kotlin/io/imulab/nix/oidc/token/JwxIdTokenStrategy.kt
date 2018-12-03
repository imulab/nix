package io.imulab.nix.oidc.token

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.token.mustKeyForJweKeyManagement
import io.imulab.nix.oauth.token.mustKeyForSignature
import io.imulab.nix.oauth.token.resolvePrivateKey
import io.imulab.nix.oauth.token.resolvePublicKey
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.jwk.setAcr
import io.imulab.nix.oidc.jwk.setAuthTime
import io.imulab.nix.oidc.jwk.setNonce
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.ReservedClaimNames
import org.jose4j.keys.AesKey

/**
 * A JWT/JWE implementation to the [IdTokenStrategy].
 */
class JwxIdTokenStrategy(
    private val oidcContext: OidcContext,
    private val jsonWebKeySetStrategy: JsonWebKeySetStrategy
) : IdTokenStrategy {

    /**
     * A controlled list of id token claim names that this strategy
     * will explicitly set.
     */
    private val controlledClaims = setOf(
        ReservedClaimNames.JWT_ID,
        ReservedClaimNames.ISSUED_AT,
        ReservedClaimNames.NOT_BEFORE,
        ReservedClaimNames.EXPIRATION_TIME,
        ReservedClaimNames.ISSUER,
        ReservedClaimNames.SUBJECT,
        ReservedClaimNames.AUDIENCE,
        IdTokenClaim.nonce,
        IdTokenClaim.authTime,
        IdTokenClaim.acr
    )

    /**
     * Generate an id token. A JWT token containing id token claims will first be generated. And then it will be
     * optionally encrypted when client is configured to do so.
     */
    override suspend fun generateToken(request: OAuthRequest): String {
        val session = request.session.assertType<OidcSession>()

        val client = request.client.assertType<OidcClient>()
        // Get the jwks here asynchronously to save time.
        val clientJwks: Deferred<JsonWebKeySet> = withContext(Dispatchers.IO) {
            async { jsonWebKeySetStrategy.resolveKeySet(client) }
        }

        val claims = generateClaims(session, client)

        return when (client.idTokenEncryptedResponseAlgorithm) {
            JweKeyManagementAlgorithm.None -> {
                clientJwks.cancel() // we actually don't need client jwks, cancel it.
                signToken(claims, client)
            }
            else -> encryptToken(
                token = signToken(claims, client),
                client = client,
                clientJwks = clientJwks.await()
            )
        }
    }

    private fun generateClaims(session: OidcSession, client: OidcClient): JwtClaims {
        return JwtClaims().also { c ->
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setExpirationTimeMinutesInTheFuture(oidcContext.idTokenLifespan.toMinutes().toFloat())
            c.setNotBeforeMinutesInThePast(0f)
            c.issuer = oidcContext.issuerUrl
            c.setAudience(client.id)
            c.subject = session.obfuscatedSubject
            if (session.authTime != null)
                c.setAuthTime(session.authTime!!)
            if (session.nonce.isNotEmpty())
                c.setNonce(session.nonce)
            if (session.acrValues.isNotEmpty())
                c.setAcr(session.acrValues)

            session.idTokenClaims
                .filterKeys { !controlledClaims.contains(it) }
                .forEach { t, u -> c.setClaim(t, u) }
        }
    }

    private fun signToken(claims: JwtClaims, client: OidcClient): String {
        val jws = JsonWebSignature().also { s ->
            s.payload = claims.toJson()
            s.algorithmHeaderValue = client.idTokenSignedResponseAlgorithm.algorithmIdentifier
        }

        when (client.idTokenSignedResponseAlgorithm) {
            JwtSigningAlgorithm.None -> jws.setAlgorithmConstraints(JwtSigningAlgorithm.None.whitelisted())
            JwtSigningAlgorithm.HS256,
            JwtSigningAlgorithm.HS384,
            JwtSigningAlgorithm.HS512 -> jws.key = AesKey(client.secret)
            else -> {
                val jwk = oidcContext.masterJsonWebKeySet.mustKeyForSignature(client.idTokenSignedResponseAlgorithm)
                jws.key = jwk.resolvePrivateKey()
                jws.keyIdHeaderValue = jwk.keyId
            }
        }

        return jws.compactSerialization
    }

    private fun encryptToken(token: String, client: OidcClient, clientJwks: JsonWebKeySet): String {
        return JsonWebEncryption().also { jwe ->
            jwe.setPlaintext(token)
            jwe.contentTypeHeaderValue = "JWT"
            jwe.algorithmHeaderValue = client.idTokenEncryptedResponseAlgorithm.algorithmIdentifier
            jwe.encryptionMethodHeaderParameter = client.idTokenEncryptedResponseEncoding.algorithmIdentifier
            jwe.key = clientJwks.mustKeyForJweKeyManagement(client.idTokenEncryptedResponseAlgorithm).resolvePublicKey()
        }.compactSerialization
    }
}