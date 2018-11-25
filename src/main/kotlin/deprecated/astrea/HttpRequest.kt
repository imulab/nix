package deprecated.astrea

import io.imulab.astrea.error.InvalidRequestException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.UrlValues
import io.ktor.application.ApplicationCall
import io.ktor.http.HttpMethod
import io.ktor.request.ContentTransformationException
import io.ktor.request.httpMethod
import io.ktor.request.receiveParameters
import io.ktor.util.toMap
import kotlinx.coroutines.runBlocking

class HttpRequest(private val call: ApplicationCall): HttpRequestReader {

    private val myForm: UrlValues by lazy {
        runBlocking {
            when (call.request.httpMethod) {
                HttpMethod.Get -> call.request.queryParameters
                else -> call.receiveParameters()
            }
        }.toMap()
    }

    override fun getForm(): UrlValues = try { myForm } catch (e: ContentTransformationException) {
        throw CannotParseFormException()
    }

    override fun getHeader(key: String): String = call.request.headers[key] ?: ""

    override fun method(): String = call.request.httpMethod.value

    private class CannotParseFormException: InvalidRequestException(
        "Cannot read request form. Is Content-Type header set to application/x-www-form-urlencoded?"
    )
}