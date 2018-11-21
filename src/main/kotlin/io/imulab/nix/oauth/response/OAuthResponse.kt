package io.imulab.nix.oauth.response

interface OAuthResponse {

    fun getStatus(): Int

    fun getExtraHeaders(): Map<String, String>

    fun getParameters(): Map<String, String>
}