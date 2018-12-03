package io.imulab.nix.oidc.spi

interface HttpResponse {

    fun status(): Int

    fun body(): String
}