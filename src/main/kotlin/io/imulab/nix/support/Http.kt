package io.imulab.nix.support

import io.imulab.nix.constant.Misc
import io.ktor.client.response.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.expires
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