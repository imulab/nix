package io.imulab.nix.oauth.request

import java.time.LocalDateTime

open class OAuthSession(
    var subject: String = "",
    var originalRequestTime: LocalDateTime? = null,
    val grantedScopes: MutableSet<String> = mutableSetOf(),
    val accessTokenClaims: MutableMap<String, Any> = mutableMapOf()
)