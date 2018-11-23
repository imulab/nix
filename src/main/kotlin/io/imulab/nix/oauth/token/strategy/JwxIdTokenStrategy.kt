package io.imulab.nix.oauth.token.strategy

import io.imulab.astrea.domain.extension.optionalStringClaim
import io.imulab.nix.client.OidcClient
import io.imulab.nix.constant.Error
import io.imulab.nix.constant.StandardClaims
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.request.OidcRequest
import io.imulab.nix.oauth.request.TokenRequest
import io.imulab.nix.oauth.session.OidcSession
import io.imulab.nix.oauth.token.JweToken
import io.imulab.nix.oauth.token.JwtToken
import io.imulab.nix.oauth.token.Token
import io.imulab.nix.oauth.token.TokenType
import io.imulab.nix.oauth.vor.JsonWebKeySetVor
import io.imulab.nix.support.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import java.time.Duration
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAmount

class JwxIdTokenStrategy(
    private val issuer: String,
    private val serverJwks: JsonWebKeySet,
    private val jwksVor: JsonWebKeySetVor,
    private val idTokenLifespan: TemporalAmount = Duration.ofHours(24)
) : IdTokenStrategy {

    override suspend fun generateIdToken(request: OidcRequest, coroutineScope: CoroutineScope): Token {
        val session = request.session.assertType<OidcSession>()

        require(session.idTokenClaims.subject.isNotEmpty()) {
            "oidc session id token subject claim is not set, did upstream overlook this?"
        }
        require(request.client is OidcClient) {
            "${javaClass.name} can only process requests from OidcClient."
        }

        val client = (request.client as OidcClient).also {
            if (request is AuthorizeRequest && it.idTokenSignedResponseAlgorithm == SigningAlgorithm.None)
                throw Error.Jwk.noneAlgorithmAtAuthorizeEndpoint()
        }

        val serverSigningKey: JsonWebKey = serverJwks.findKeyForSignature(client.idTokenSignedResponseAlgorithm)
        val clientEncryptionKey: Deferred<JsonWebKey>? =
            if (client.idTokenEncryptedResponseAlgorithm == null) null else {
                requireNotNull(client.idTokenEncryptedResponseEncoding)
                coroutineScope.async(Dispatchers.IO) {
                    jwksVor.resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
                        ?.findKeyForJweKeyManagement(client.idTokenEncryptedResponseAlgorithm!!)
                        ?: throw Error.Jwks.noJwks()
                }
            }

        request.ensureValidAuthenticationState()

        if (session.idTokenClaims.maybeAcr().isEmpty())
            session.idTokenClaims.setAcr("0")
        if (session.idTokenClaims.maybeAzp().isEmpty())
            session.idTokenClaims.setAzp(client.id)

        val token = JsonWebSignature().also { jws ->
            jws.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.issuer = issuer
                c.setAudience(client.id)
                c.subject = session.subject.switchOnEmpty(session.idTokenClaims.subject)
                c.issuedAt = NumericDate.now()
                c.setExpirationTimeMinutesInTheFuture(idTokenLifespan.get(ChronoUnit.SECONDS).div(60).toFloat())

                c.setAuthTime(session.idTokenClaims.maybeAuthTime() ?: NumericDate.now())
                c.setNonce(request.nonce)
                c.setAcr(session.idTokenClaims.maybeAcr())
                c.setAmr(session.idTokenClaims.maybeAmr())
                c.setAzp(session.idTokenClaims.maybeAzp())

                if (session.idTokenClaims.maybeAccessTokenHash().isNotEmpty())
                    c.setAccessTokenHash(session.idTokenClaims.maybeAccessTokenHash())
                if (session.idTokenClaims.maybeCodeHash().isNotEmpty())
                    c.setCodeHash(session.idTokenClaims.maybeCodeHash())

                StandardClaims.allClaims.forEach { sc ->
                    if (session.idTokenClaims.hasClaim(sc))
                        c.setClaim(sc, session.idTokenClaims.getClaimValue(sc))
                }
            }.toJson()
            jws.keyIdHeaderValue = serverSigningKey.keyId
            jws.algorithmHeaderValue = serverSigningKey.algorithm
            jws.key = serverSigningKey.resolvePrivateKey()
        }.compactSerialization

        if (client.idTokenEncryptedResponseAlgorithm == null)
            return JwtToken(type = TokenType.IdToken, raw = token)

        val encryptedToken = JsonWebEncryption().also { jwe ->
            jwe.setPlaintext(token)
            jwe.contentTypeHeaderValue = "JWT"
            jwe.encryptionMethodHeaderParameter = client.idTokenEncryptedResponseEncoding!!.alg
            jwe.algorithmHeaderValue = client.idTokenEncryptedResponseAlgorithm!!.identifier
            jwe.key = clientEncryptionKey!!.await().resolvePublicKey()
        }.compactSerialization
        return JweToken(type = TokenType.IdToken, raw = encryptedToken)
    }
}