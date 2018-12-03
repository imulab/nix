package io.imulab.nix.oauth.response

/**
 * Interface for an authorization response.
 */
interface AuthorizationCodeResponse {

    /**
     * The authorization code
     */
    var code: String

    /**
     * The state parameter, if included in request
     */
    var state: String

    /**
     * The scope parameter, if not empty
     */
    var scope: Set<String>

}