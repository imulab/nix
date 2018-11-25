package deprecated.oauth.vor

import deprecated.client.OidcClient
import deprecated.constant.Error
import deprecated.persistence.Cache
import deprecated.support.effectiveExpiry
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.call.receive
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.lang.JoseException

class JsonWebKeySetVor(
    private val jwksCache: Cache<String, String>,
    override val httpClient: HttpClient
) : ValueOrReference<String, JsonWebKeySet, OidcClient> {

    override val cache: Cache<String, String>
        get() = jwksCache

    private fun String.asJwks(): JsonWebKeySet {
        return try {
            JsonWebKeySet(this)
        } catch (e: JoseException) {
            throw Error.Jwks.invalid()
        }
    }

    override suspend fun resolve(value: String, reference: String, context: OidcClient): JsonWebKeySet? {
        val jwksValue = when {
            value.isEmpty() && reference.isEmpty() -> null
            value.isEmpty() && reference.isNotEmpty() -> withContext(Dispatchers.IO) {
                jwksCache.read(reference) ?: httpClient.call(reference).response.let { httpResponse ->
                    when (httpResponse.status) {
                        HttpStatusCode.OK -> {
                            httpResponse.receive<String>().also { v ->
                                try {
                                    JsonWebKeySet(v)
                                    launch { jwksCache.write(reference, v, httpResponse.effectiveExpiry()) }
                                } catch (e: JoseException) {
                                    throw Error.Jwks.invalid()
                                }
                            }
                        }
                        else -> throw Error.Jwks.noJwks()
                    }
                }
            }
            else -> value
        }

        return jwksValue?.asJwks()
    }
}