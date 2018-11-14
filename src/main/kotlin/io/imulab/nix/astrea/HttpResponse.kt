package io.imulab.nix.astrea

import io.imulab.astrea.spi.http.HttpResponseWriter
import io.ktor.application.ApplicationCall
import io.ktor.http.HttpStatusCode
import io.ktor.response.header
import io.ktor.response.respondBytes
import kotlinx.coroutines.runBlocking

class HttpResponse(private val call: ApplicationCall): HttpResponseWriter {

    override fun setHeader(name: String, value: String) {
        call.response.header(name, value)
    }

    override fun setStatus(status: Int) {
        call.response.status(HttpStatusCode.fromValue(status))
    }

    override fun writeBody(data: ByteArray) {
        runBlocking {
            call.respondBytes(data)
        }
    }
}