package io.imulab.nix.oauth.request

import java.time.LocalDateTime

open class OAuthSession(
    var subject: String = "",
    var originalRequestTime: LocalDateTime? = null
)