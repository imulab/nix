package io.imulab.nix.server

import io.imulab.nix.oauth.InvalidRequest
import io.ktor.application.ApplicationCall
import io.ktor.config.ApplicationConfig
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.Parameters
import io.ktor.request.contentType
import io.ktor.request.httpMethod
import io.ktor.request.receiveParameters
import io.ktor.util.KtorExperimentalAPI
import io.ktor.util.StringValues
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.longPropertyOrNull(path: String): Long? {
    return this.propertyOrNull(path)?.getString()?.toLongOrNull()
}

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.intPropertyOrNull(path: String): Int? {
    return this.propertyOrNull(path)?.getString()?.toIntOrNull()
}

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.stringPropertyOrNull(path: String): String? {
    return this.propertyOrNull(path)?.getString()
}

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.stringListPropertyOrNull(path: String): List<String>? {
    return this.propertyOrNull(path)?.getList()
}

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.booleanPropertyOrNull(path: String): Boolean? {
    return this.propertyOrNull(path)?.getString()?.toBoolean()
}

suspend fun ApplicationCall.autoParameters(): Parameters {
    return when (request.httpMethod) {
        HttpMethod.Get -> request.queryParameters
        HttpMethod.Post -> {
            if (request.contentType() == ContentType.Application.FormUrlEncoded)
                withContext(Dispatchers.IO) {
                    kotlin.run { receiveParameters() }
                }
            else
                throw InvalidRequest.unmet("""
                    Content-Type header set to ${ContentType.Application.FormUrlEncoded} when doing POST
                """.trimIndent())

        }
        else -> throw UnsupportedOperationException("""
            Automatically resolving parameters for ${request.httpMethod.value} operations is not supported.
        """.trimIndent())
    }
}

fun StringValues.toMutableMap(): MutableMap<String, List<String>> =
    entries().associateByTo(LinkedHashMap(), { it.key }, { it.value.toList() })

