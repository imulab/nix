package io.imulab.nix.oauth.vor

import io.imulab.nix.client.OAuthClient
import io.imulab.nix.client.OidcClient
import io.imulab.nix.constant.ErrorCode.Sub.VALUE_AND_REFERENCE
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.error.InvalidRequestObjectException
import io.imulab.nix.error.JwkException.Companion.JwkSeekException
import io.imulab.nix.persistence.Cache
import io.imulab.nix.support.effectiveExpiry
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.response.HttpResponse
import io.ktor.client.response.readText
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class OidcRequestObjectVor(
    private val jsonWebKeySetVor: JsonWebKeySetVor,
    private val requestObjectCache: Cache<String, String>,
    private val cacheCoroutineScope: CoroutineScope,
    override val httpClient: HttpClient,
    private val jwxProvider: JwxProvider
) : ValueOrReference<String, String, Deferred<OAuthClient>> {

    override val cache: Cache<String, String>
        get() = requestObjectCache

    @Suppress("UNCHECKED_CAST")
    override suspend fun transformFromValue(value: String, context: Deferred<OAuthClient>): String? {
        val client = context.await().let {
            assert(it is OidcClient) { "client must be an OidcClient" }
            it as OidcClient
        }

        return if (client.requestObjectEncryptionAlgorithm == null) value else {
            requireNotNull(client.requestObjectEncryptionAlgorithm)
            requireNotNull(client.requestObjectEncryptionEncoding)
            jwxProvider.decryptJsonWebEncryption(
                encrypted = value,
                key = jsonWebKeySetVor.resolveIdTokenEncryptionKey(client)?.key
                    ?: throw JwkSeekException(),
                keyAlg = client.requestObjectEncryptionAlgorithm!!,
                encAlg = client.requestObjectEncryptionEncoding!!)
        }
    }

    override suspend fun extractFromHttpResponse(response: HttpResponse): String? {
        if (response.status == HttpStatusCode.OK)
            return response.readText(StandardCharsets.UTF_8)
        throw InvalidRequestObjectException("Failed to retrieve request object (code ${response.status.value}).")
    }

    override suspend fun resolve(value: String, reference: String, context: Deferred<OAuthClient>): String? {
        val request = when {
            value.isNotEmpty() && reference.isNotEmpty() ->
                throw InvalidRequestException(VALUE_AND_REFERENCE, "request object and reference both present.")
            value.isEmpty() && reference.isNotEmpty() ->
                requestObjectCache.read(reference) ?: httpClient.call(reference).response.let { httpResponse ->
                    extractFromHttpResponse(httpResponse).also { v ->
                        if (v != null)
                            cacheCoroutineScope.launch {
                                requestObjectCache.write(reference, v, httpResponse.effectiveExpiry())
                            }
                    }
                }
            else -> value
        }

        return if (request.isNullOrEmpty()) null else
            transformFromValue(request, context)
    }
}