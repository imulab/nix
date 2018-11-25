package deprecated.oauth.vor

import deprecated.persistence.Cache
import io.ktor.client.HttpClient

interface ValueOrReference<T, R, C> {

    val cache: Cache<String, T>

    val httpClient: HttpClient

    suspend fun resolve(value: T, reference: String, context: C): R?
}