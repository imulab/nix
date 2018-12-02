package io.imulab.nix.server.authz.consent.session

import java.time.LocalDateTime

data class ConsentSession(
    val subject: String,
    val grantedScopes: Set<String>,
    val claims: Map<String, Any>,
    val expiry: LocalDateTime
)