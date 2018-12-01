package io.imulab.nix.oidc.reserved

/**
 * Supplement to [io.imulab.nix.oauth.ResponseType]. The OIDC specification defines a new
 * response type `id_token`.
 */
object ResponseType {
    const val idToken = "id_token"
}