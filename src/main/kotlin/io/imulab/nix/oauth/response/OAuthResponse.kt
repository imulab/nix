package io.imulab.nix.oauth.response

/**
 * Interface to obtain response data for rendering as HTTP response.
 */
interface OAuthResponse {

    /**
     * Http response status. Default to 200
     */
    val status: Int

    /**
     * Http headers. Default to empty
     */
    val headers: Map<String, String>

    /**
     * Response data.
     */
    val data: Map<String, String>
}