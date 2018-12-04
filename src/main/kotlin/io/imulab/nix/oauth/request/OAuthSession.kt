package io.imulab.nix.oauth.request

import java.time.LocalDateTime

open class OAuthSession(
    var subject: String = "",
    var originalRequestTime: LocalDateTime? = null,
    val grantedScopes: MutableSet<String> = mutableSetOf(),
    val accessTokenClaims: MutableMap<String, Any> = mutableMapOf()
) {

    open fun merge(another: OAuthSession) {
        if (subject.isEmpty())
            subject = another.subject
        if (originalRequestTime == null)
            originalRequestTime = another.originalRequestTime
        grantedScopes.addAll(another.grantedScopes)
        accessTokenClaims.putAll(another.accessTokenClaims)
    }
}