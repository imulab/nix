package io.imulab.nix.server.http

import io.imulab.nix.oidc.spi.HttpResponse
import io.imulab.nix.oidc.spi.SimpleHttpClient
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono

object SpringHttpClient: SimpleHttpClient {

    override suspend fun get(url: String): HttpResponse {
        val response = WebClient
            .create(url)
            .get()
            .exchange()
            .block()
        return response?.let { WebClientResponse(it) } ?: NotFoundResponse
    }

    class WebClientResponse(private val response: ClientResponse): HttpResponse {

        override fun status(): Int = response.rawStatusCode()

        override fun body(): String {
            return response.bodyToMono<String>().block() ?: ""
        }
    }

    object NotFoundResponse : HttpResponse {
        override fun status(): Int = 404

        override fun body(): String = ""
    }
}