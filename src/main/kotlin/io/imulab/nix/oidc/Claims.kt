package io.imulab.nix.oidc

data class Claims(var userInfo: Map<String, ClaimInfo?>? = null,
                  var idToken: Map<String, ClaimInfo?>? = null)

data class ClaimInfo(var essential: Boolean = false,
                     var values: List<String> = emptyList())

/**
 * Provide functions to convert [Claims] object to and from JSON.
 */
interface ClaimsJsonConverter {
    fun toJson(claims: Claims): String
    fun fromJson(value: String): Claims
}