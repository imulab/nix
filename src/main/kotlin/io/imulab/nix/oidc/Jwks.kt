package io.imulab.nix.oidc

import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oidc.client.OidcClient
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.call.receive
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jose4j.jwk.*
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.JsonWebStructure
import org.jose4j.keys.resolvers.VerificationKeyResolver
import org.jose4j.lang.JoseException
import java.security.Key

/**
 * Data management interface for saved Json Web Key Sets.
 */
interface JsonWebKeySetRepository {

    /**
     * Returns the special json web key set belongs to the server
     */
    suspend fun getServerJsonWebKeySet(): JsonWebKeySet

    /**
     * Returns the json web key set identifiable by the [jwksUri]
     */
    suspend fun getClientJsonWebKeySet(jwksUri: String): JsonWebKeySet?

    /**
     * Associate the [keySet] with the [jwksUri] and write to the repository
     */
    suspend fun writeClientJsonWebKeySet(jwksUri: String, keySet: JsonWebKeySet)
}

/**
 * Logic to resolve a Json Web Key Set for client via its registered jwks_uri and jwks parameter:
 *
 * When both parameter is empty, it returns an empty [JsonWebKeySet]. When both parameter is specified,
 * it raises server_error.
 *
 * If [OidcClient.jwks] is not empty, it parses it into [JsonWebKeySet] and returns.
 *
 * If [OidcClient.jwksUri] is not empty, it first tries to find a saved key set from [jsonWebKeySetRepository]. If no
 * avail, it will try to fetch it from this uri, parse the response content, save it and return it.
 *
 * Note that this strategy DOES NOT take care of removing the old jwks cache in the case of client updating the
 * registered jwks_uri value. Client registration process must tend to that.
 */
class JsonWebKeySetStrategy(
    private val jsonWebKeySetRepository: JsonWebKeySetRepository,
    private val httpClient: HttpClient
) {

    suspend fun resolveKeySet(client: OidcClient): JsonWebKeySet = try {
        doResolveKeySet(client)
    } catch (e: JoseException) {
        throw ServerError.internal("Invalid json web key set.")
    }

    private suspend fun doResolveKeySet(client: OidcClient): JsonWebKeySet {
        if (client.jwks.isNotEmpty()) {
            check(client.jwksUri.isEmpty()) {
                """
                    Client jwks and jwks_uri cannot be both registered.
                    If jwks_uri can be used, client must not use jwks.
                """.trimIndent()
            }

            return JsonWebKeySet(client.jwks)
        }

        if (client.jwksUri.isNotEmpty()) {
            val saved = jsonWebKeySetRepository.getClientJsonWebKeySet(client.jwksUri)
            if (saved != null)
                return saved
            return fetchFromRemote(client.jwksUri)
        }

        return JsonWebKeySet()
    }

    private suspend fun fetchFromRemote(jwksUri: String): JsonWebKeySet = withContext(Dispatchers.IO) {
        run {
            httpClient.call(jwksUri).response.let { httpResponse ->
                when (httpResponse.status) {
                    HttpStatusCode.OK -> {
                        httpResponse.receive<String>().let { v ->
                            JsonWebKeySet(v).also {
                                launch {
                                    jsonWebKeySetRepository.writeClientJsonWebKeySet(
                                        jwksUri = jwksUri,
                                        keySet = it
                                    )
                                }
                            }
                        }
                    }
                    else -> throw ServerError.internal("call to jwks_uri returned ${httpResponse.status.value}.")
                }
            }
        }
    }
}

class JwtVerificationKeyResolver(
    private val jwks: JsonWebKeySet,
    private val signAlg: JwtSigningAlgorithm
): VerificationKeyResolver {

    override fun resolveKey(jws: JsonWebSignature?, nestingContext: MutableList<JsonWebStructure>?): Key {
        requireNotNull(jws) {
            "Json web signature must exist."
        }

        return if (jws.keyIdHeaderValue != null)
            jwks.mustKeyWithId(jws.keyIdHeaderValue).resolvePublicKey()
        else
            jwks.mustKeyForSignature(signAlg).resolvePublicKey()
    }
}

/**
 * Resolves the private key of the json web key for signing and decryption.
 * If [this] is a symmetric key (octet-sequence), returns the key directly.
 */
fun JsonWebKey.resolvePrivateKey(): Key = when(this) {
    is RsaJsonWebKey -> this.rsaPrivateKey
    is EllipticCurveJsonWebKey -> this.ecPrivateKey
    is PublicJsonWebKey -> this.privateKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

/**
 * Resolves the public key of the json web key for signature verification and encryption.
 * If [this] is a symmetric key (octet-sequence), returns the key directly.
 */
fun JsonWebKey.resolvePublicKey(): Key = when(this) {
    is RsaJsonWebKey -> this.getRsaPublicKey()
    is EllipticCurveJsonWebKey -> this.ecPublicKey
    is PublicJsonWebKey -> this.publicKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

fun JsonWebKeySet.mustKeyForJweKeyManagement(keyAlg: JweKeyManagementAlgorithm): JsonWebKey =
    this.findJsonWebKey(null, null, Use.ENCRYPTION, keyAlg.algorithmIdentifier)
        ?: throw ServerError.internal("Cannot find key for managing ${keyAlg.spec}.")

fun JsonWebKeySet.mustKeyForSignature(signAlg: JwtSigningAlgorithm): JsonWebKey =
        this.findJsonWebKey(null, null, Use.SIGNATURE, signAlg.algorithmIdentifier)
        ?: throw ServerError.internal("Cannot find key for signing ${signAlg.spec}.")

fun JsonWebKeySet.mustKeyWithId(keyId: String): JsonWebKey =
        this.findJsonWebKey(keyId, null, null, null)
            ?: throw ServerError.internal("Cannot find key with id $keyId.")