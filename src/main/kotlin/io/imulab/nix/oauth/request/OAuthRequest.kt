package io.imulab.nix.oauth.request

import io.imulab.nix.oauth.client.OAuthClient
import java.time.LocalDateTime
import java.util.*

/**
 * Super class of all OAuthConfig requests.
 */
open class OAuthRequest(
    val id: String = UUID.randomUUID().toString(),
    val requestTime: LocalDateTime = LocalDateTime.now(),
    val client: OAuthClient,
    val session: OAuthSession = OAuthSession()
)