package io.imulab.nix.oauth.response

interface AccessTokenResponse {
    /**
     * The access token issued by the authorization server.
     */
    var accessToken: String
    /**
     * The type of the token issued.
     */
    var tokenType: String
    /**
     * The lifetime in seconds of the access token.
     */
    var expiresIn: Long
    /**
     * The refresh token issued by the authorization server, if any.
     */
    var refreshToken: String
    /**
     * The array of granted scopes, if different with the requested values.
     */
    var scope: Set<String>
    /**
     * The state from the authorize request, if any.
     */
    var state: String
}