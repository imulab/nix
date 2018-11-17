package io.imulab.nix.astrea

import io.imulab.astrea.spi.http.HttpResponseWriter
import io.ktor.application.ApplicationCall
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.response.header
import io.ktor.response.respond
import io.ktor.response.respondBytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking

class HttpResponse(private val call: ApplicationCall, private val scope: CoroutineScope): HttpResponseWriter {

    private var hasBody: Boolean = false

    override fun setHeader(name: String, value: String) {
        when (name) {
            HttpHeaders.ContentType -> { /* content-type is controlled by framework */ }
            else -> call.response.header(name, value)
        }
    }

    override fun setStatus(status: Int) {
        call.response.status(HttpStatusCode.fromValue(status))
    }

    override fun writeBody(data: ByteArray) {
        runBlocking(scope.coroutineContext) {
            println(String(data))
            call.respondBytes(data)
        }
        hasBody = true
    }

    fun flush() {
        if (!hasBody)
            runBlocking {
                call.respond("")
            }
    }
}