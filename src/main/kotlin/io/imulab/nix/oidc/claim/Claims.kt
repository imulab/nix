package io.imulab.nix.oidc.claim

data class Claims(var userInfo: Map<String, ClaimInfo?>? = null,
                  var idToken: Map<String, ClaimInfo?>? = null) {

    fun isEmpty(): Boolean =
        (userInfo == null || userInfo?.isEmpty() == true) && (idToken == null || idToken?.isEmpty() == true)

    fun hasEssentialClaim(name: String): Boolean =
            userInfo?.get(name)?.essential
                ?: idToken?.get(name)?.essential
                ?: false
}