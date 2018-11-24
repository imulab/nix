package io.imulab.nix.oauth.vor

import io.imulab.nix.constant.Error
import io.imulab.nix.constant.Error.Sub.VALUE_AND_REFERENCE
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.persistence.Cache
import io.imulab.nix.support.effectiveExpiry
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.response.readText
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

class RequestObjectVor(
    private val requestObjectCache: Cache<String, String>,
    override val httpClient: HttpClient
) : ValueOrReference<String, String, Any?> {

    override val cache: Cache<String, String>
        get() = requestObjectCache

    override suspend fun resolve(value: String, reference: String, context: Any?): String? {
        val request = when {
            value.isNotEmpty() && reference.isNotEmpty() ->
                throw InvalidRequestException(VALUE_AND_REFERENCE, "request object and reference both present.") // TODO replace this
            value.isEmpty() && reference.isNotEmpty() -> withContext(Dispatchers.IO) {
                requestObjectCache.read(reference) ?: httpClient.call(reference).response.let { httpResponse ->
                    when (httpResponse.status) {
                        HttpStatusCode.OK -> httpResponse.readText(StandardCharsets.UTF_8).also { v ->
                            if (v.isNotEmpty())
                                launch { requestObjectCache.write(reference, v, httpResponse.effectiveExpiry()) }
                        }
                        else -> throw Error.RequestObject.acquireFailed()
                    }
                }
            }
            else -> value
        }

        return if (request.isEmpty()) null else request
    }
}