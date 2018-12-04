package io.imulab.nix.oidc.response

interface IdTokenResponse {
    /**
     * The generated id token
     */
    var idToken: String
}