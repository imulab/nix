package deprecated.oauth.token.strategy

import deprecated.client.OidcClient
import deprecated.constant.Error
import deprecated.constant.Misc
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.crypt.sign.JwtVerificationKeyResolver
import deprecated.oauth.vor.JsonWebKeySetVor
import deprecated.support.findKeyForJweKeyManagement
import deprecated.support.resolvePrivateKey
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext

/**
 * Strategy to handle an Open ID Connect request object, either encrypted or decrypted, signed or unsigned.
 */
interface RequestObjectStrategy {

    /**
     * Decrypt the request object which is known to have been encrypted. The output would be
     * the decrypted plain text payload of the JWE token.
     */
    fun decryptRequestObject(encryptedRequest: String, client: OidcClient): String

    /**
     * Decode the request object, which could be encrypted. In case it is encrypted, [decryptRequestObject] will
     * be called first before it is decoded as a plain JWT.
     */
    suspend fun decodeRequestObject(request: String, client: OidcClient): JwtContext

    /**
     * Tests if the request object is encrypted.
     */
    suspend fun isRequestObjectEncrypted(token: String, client: OidcClient): Boolean =
        when {
            client.requestObjectEncryptionAlgorithm == null -> false
            token.split(Misc.DOT).size == 3 -> false
            else -> true
        }

    /**
     * Worry free method to call if we just want to see what's inside the request object token.
     */
    suspend fun resolveRequestObject(token: String, client: OidcClient): JwtContext {
        return token.let { t ->
            if (isRequestObjectEncrypted(t, client))
                decryptRequestObject(t, client)
            else
                t
        }.let { t ->
            decodeRequestObject(t, client)
        }
    }
}

/**
 * Implementation of [RequestObjectStrategy]
 *
 * If client asserts that its request object is an encrypted JWT (by configuring
 * request_object_encryption_alg and request_object_encryption_enc), we need to decrypt
 * it first using the server's private key.
 *
 * If client asserts that its request object is an unencrypted JWT (by leaving
 * request_object_encryption_alg blank), then we pass on the request object as to next stage.
 *
 * The JWT needs to be verified. According to OIDC spec: "The Request Object MAY be signed or unsigned (plaintext)".
 *
 * When it is plaintext, this is indicated by use of the none algorithm in the JOSE Header.
 *
 * If signed, the Request Object SHOULD contain the Claims iss (issuer) and aud (audience) as members.
 * The iss value SHOULD be the Client ID of the RP, unless it was signed by a different party than the RP.
 * The aud value SHOULD be or include the OP's Issuer Identifier URL.
 */
class JwxRequestObjectStrategy(
    private val serverJwks: JsonWebKeySet,
    private val clientJwksVor: JsonWebKeySetVor,
    private val expectedAudience: String
): RequestObjectStrategy {

    override fun decryptRequestObject(encryptedRequest: String, client: OidcClient): String {
        requireNotNull(client.requestObjectEncryptionAlgorithm)
        requireNotNull(client.requestObjectEncryptionEncoding)
        return serverJwks.findKeyForJweKeyManagement(client.requestObjectEncryptionAlgorithm!!).let { jwk ->
            JsonWebEncryption().also { jwe ->
                jwe.setAlgorithmConstraints(client.requestObjectEncryptionAlgorithm!!.asAlgorithmConstraint())
                jwe.setContentEncryptionAlgorithmConstraints(client.requestObjectEncryptionEncoding!!.asAlgorithmConstraint())
                jwe.compactSerialization = encryptedRequest
                jwe.key = jwk.resolvePrivateKey()
            }.plaintextString
        }
    }

    override suspend fun decodeRequestObject(request: String, client: OidcClient): JwtContext {
        return when (client.idTokenSignedResponseAlgorithm) {
            SigningAlgorithm.None -> {
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setSkipVerificationKeyResolutionOnNone()
                    .setExpectedAudience(expectedAudience)
                    .build()
                    .process(request)
            }
            else -> {
                val clientJwks = clientJwksVor.resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
                    ?: throw Error.Jwks.noJwks()
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setVerificationKeyResolver(
                        JwtVerificationKeyResolver(
                            clientJwks,
                            client.requestObjectSigningAlgorithm
                        )
                    )
                    .setExpectedIssuers(true, null)     // any value is acceptable
                    .setExpectedAudience(expectedAudience)
                    .build()
                    .process(request)
            }
        }
    }
}