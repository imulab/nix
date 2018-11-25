package deprecated.astrea

import io.imulab.astrea.spi.http.HttpResponseReader
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.engine.apache.Apache
import io.ktor.client.response.HttpResponse
import io.ktor.client.response.readBytes
import kotlinx.coroutines.runBlocking

object HttpClient: io.imulab.astrea.spi.http.HttpClient {

    private val client = HttpClient(Apache)

    override fun get(url: String): HttpResponseReader =
        Response(runBlocking { client.call(url).response })

    class Response(private val httpResponse: HttpResponse) : HttpResponseReader {

        override fun body(): ByteArray = runBlocking { httpResponse.readBytes() }

        override fun statusCode(): Int = httpResponse.status.value
    }
}