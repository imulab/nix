package io.imulab.nix.oauth

import java.time.Duration

/**
 * Global server configuration data.
 */
open class ServerConfiguration(
    val issuerUrl: String,
    val authorizeEndpointUrl: String,
    val tokenEndpointUrl: String,
    val defaultTokenEndpointAuthenticationMethod: String = AuthenticationMethod.clientSecretPost,
    val authorizeCodeLifespan: Duration = Duration.ofMinutes(10),
    val accessTokenLifespan: Duration = Duration.ofHours(1),
    val refreshTokenLifespan: Duration = Duration.ofDays(14)
)