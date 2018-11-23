package io.imulab.nix.support

import io.imulab.nix.constant.Error
import io.imulab.nix.constant.Misc
import io.imulab.nix.error.InvalidRequestException
import io.ktor.application.ApplicationCall
import io.ktor.client.response.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.expires
import io.ktor.request.receiveParameters
import io.ktor.util.toLocalDateTime
import java.time.LocalDateTime

fun HttpResponse.effectiveExpiry(): LocalDateTime? =
    expires()?.toLocalDateTime()
        ?: headers[HttpHeaders.CacheControl]
            ?.split(Misc.COMMA)
            ?.map { it.trim().split("=") }
            ?.find { it.size == 2 && it[0] == "max-age" }
            ?.get(1)
            ?.let { it.toLongOrNull() }
            ?.let { LocalDateTime.now().plusSeconds(it) }

suspend fun ApplicationCall.parseRequestForm(): Map<String, String> {
    return mutableMapOf<String, String>().also {
        receiveParameters().forEach { s, list ->
            when (list.size) {
                0 -> {
                }
                1 -> it[s] = list[0]
                else -> throw InvalidRequestException(
                    subCode = Error.Sub.DUPLICATE_PARAM,
                    message = "Parameters cannot be included more than once."
                )
            }
        }
    }
}