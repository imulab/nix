package io.imulab.nix.oauth.vor

import io.imulab.nix.client.OidcClient
import io.imulab.nix.constant.ErrorCode
import io.imulab.nix.error.JwkException
import io.imulab.nix.persistence.Cache
import io.imulab.nix.support.effectiveExpiry
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.call.receive
import io.ktor.client.response.HttpResponse
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.lang.JoseException
import java.security.Key

class JsonWebKeySetVor(
    private val jwksCache: Cache<String, String>,
    private val cacheCoroutineScope: CoroutineScope,
    override val httpClient: HttpClient
) : ValueOrReference<String, JsonWebKeySet, OidcClient> {

    override val cache: Cache<String, String>
        get() = jwksCache

    override suspend fun transformFromValue(value: String, context: OidcClient): JsonWebKeySet? {
        try {
            return JsonWebKeySet(value)
        } catch (e: JoseException) {
            throw JwkException(subCode = ErrorCode.Sub.INVALID_JWKS,
                message = e.message ?: "Not a valid Json Web Key Set.")
        }
    }

    override suspend fun extractFromHttpResponse(response: HttpResponse): String? {
        if (response.status != HttpStatusCode.OK)
            throw JwkException.Companion.JwksAcquireException("Attempt to download remote Json Web Key Set failed (code: ${response.status.value}).")
        return response.receive()
    }

    override suspend fun resolve(value: String, reference: String, context: OidcClient): JsonWebKeySet? {
        val jwksValue: String? = when {
            value.isEmpty() && reference.isEmpty() -> null
            value.isEmpty() && reference.isNotEmpty() -> {
                cacheCoroutineScope.run { jwksCache.read(reference) } ?: httpClient.call(reference).response.let { httpResponse ->
                    extractFromHttpResponse(httpResponse).also { v ->
                        if (v != null)
                            cacheCoroutineScope.launch {
                                jwksCache.write(reference, v, httpResponse.effectiveExpiry())
                            }
                    }
                }
            }
            else -> value
        }

        return if (jwksValue.isNullOrEmpty())
            null
        else
            transformFromValue(jwksValue, context)
    }

    suspend fun resolveIdTokenEncryptionKey(client: OidcClient): JsonWebKey? =
        if (client.idTokenEncryptedResponseAlgorithm == null)
            null
        else resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
            ?.findJsonWebKey(null, null, Use.ENCRYPTION, client.idTokenEncryptedResponseAlgorithm!!.identifier)

    suspend fun resolveRequestObjectSigningKey(client: OidcClient): JsonWebKey? =
        resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
            ?.findJsonWebKey(
                null,
                client.requestObjectSigningAlgorithm.keyType,
                Use.SIGNATURE,
                client.requestObjectSigningAlgorithm.alg)
}