package io.imulab.nix.oidc

data class Claims(var userInfo: Map<String, ClaimInfo?>? = null,
                  var idToken: Map<String, ClaimInfo?>? = null) {

    fun isEmpty(): Boolean =
        (userInfo?.isEmpty() == true) && (idToken?.isEmpty() == true)

    fun hasEssentialClaim(name: String): Boolean =
            userInfo?.get(name)?.essential
                ?: idToken?.get(name)?.essential
                ?: false
}

data class ClaimInfo(var essential: Boolean = false,
                     var values: List<String> = emptyList())

/**
 * Provide functions to convert [Claims] object to and from JSON.
 */
interface ClaimsJsonConverter {
    fun toJson(claims: Claims): String
    fun fromJson(value: String): Claims
}