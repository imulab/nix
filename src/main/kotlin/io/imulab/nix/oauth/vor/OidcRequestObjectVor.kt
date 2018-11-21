package io.imulab.nix.oauth.vor

import io.imulab.nix.client.OAuthClient
import io.imulab.nix.client.OidcClient
import io.imulab.nix.persistence.Cache
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.response.HttpResponse
import io.ktor.client.response.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.jose4j.jwt.JwtClaims
import java.nio.charset.StandardCharsets
import kotlin.coroutines.CoroutineContext

class OidcRequestObjectVor(
    private val requestObjectCache: Cache<String, String>,
    private val client: HttpClient,
    override val coroutineContext: CoroutineContext = Dispatchers.Default
) : ValueOrReference<String, JwtClaims, Deferred<OAuthClient>>, CoroutineScope {

    override val cache: Cache<String, String>
        get() = requestObjectCache
    override val httpClient: HttpClient
        get() = client

    @Suppress("UNCHECKED_CAST")
    override suspend fun transformFromValue(value: String, context: Deferred<OAuthClient>): JwtClaims? {
        val client = context.await().let {
            assert(it is OidcClient) { "client must be an OidcClient" }
            it as OidcClient
        }


        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override suspend fun extractFromHttpResponse(response: HttpResponse): String? =
        response.readText(StandardCharsets.UTF_8)

    override suspend fun resolve(value: String, reference: String, context: Deferred<OAuthClient>): JwtClaims? {
        val request = when {
            value.isNotEmpty() && reference.isNotEmpty() -> TODO("cannot provided at once")
            value.isEmpty() && reference.isNotEmpty() -> {
                requestObjectCache.read(reference) ?: client.call(reference).response.let { httpResponse ->
                    extractFromHttpResponse(httpResponse).also { v ->
                        if (v != null)
                            launch {
                                // TODO respect cache control
                                requestObjectCache.write(reference, v)
                            }
                    }
                }
            }
            else -> value
        }

        return if (request.isNullOrEmpty())
            null
        else
            transformFromValue(request, context)
    }
}