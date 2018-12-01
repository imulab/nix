package io.imulab.nix.oidc.claim

/**
 * Provide functions to convert [Claims] object to and from JSON.
 */
interface ClaimsJsonConverter {
    fun toJson(claims: Claims): String
    fun fromJson(value: String): Claims
}