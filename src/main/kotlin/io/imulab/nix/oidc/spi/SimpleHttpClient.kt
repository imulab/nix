package io.imulab.nix.oidc.spi

interface SimpleHttpClient {

    suspend fun get(url: String): HttpResponse
}