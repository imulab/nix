package io.imulab.nix.oauth.vor

import io.imulab.nix.persistence.Cache
import io.ktor.client.HttpClient
import io.ktor.client.response.HttpResponse

interface ValueOrReference<T, R, C> {

    val cache: Cache<String, T>

    val httpClient: HttpClient

    suspend fun transformFromValue(value: T, context: C): R?

    suspend fun extractFromHttpResponse(response: HttpResponse): T?

    suspend fun resolve(value: T, reference: String, context: C): R?
}