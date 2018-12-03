package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.request.OAuthSession
import java.time.LocalDateTime

/**
 * Open ID Connect User Session.
 */
open class OidcSession(
    subject: String = "",
    var obfuscatedSubject: String = "",
    var authTime: LocalDateTime? = null,
    var acrValues: MutableList<String> = mutableListOf(),
    val idTokenClaims: MutableMap<String, Any> = mutableMapOf()
) : OAuthSession(subject)