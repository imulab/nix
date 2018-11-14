package io.imulab.nix.astrea

import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.UrlValues
import io.ktor.application.ApplicationCall
import io.ktor.http.HttpMethod
import io.ktor.request.httpMethod
import io.ktor.request.receiveParameters
import io.ktor.util.toMap
import kotlinx.coroutines.runBlocking

class HttpRequest(private val call: ApplicationCall): HttpRequestReader {

    override fun formValue(key: String): String {
        throw UnsupportedOperationException("not implementation since deprecated")
    }

    override fun formValueUnescaped(key: String): String {
        throw UnsupportedOperationException("not implementation since deprecated")
    }

    override fun getForm(): UrlValues {
        val parameters = runBlocking {
            when (call.request.httpMethod) {
                HttpMethod.Get -> call.request.queryParameters
                else -> call.receiveParameters()
            }
        }
        return parameters.toMap()
    }

    override fun getHeader(key: String): String = call.request.headers[key] ?: ""

    override fun method(): String = call.request.httpMethod.value
}