package deprecated.client.sector

/**
 * Result wrapper for the set of redirect uris obtained from sector_identifier_uri.
 *
 * @property redirectUris the set of redirect uris.
 * @property ttlSeconds the number of seconds to live until this expires and should no longer be considered valid.
 *                      If null, consider this never expires.
 */
data class RemoteRedirectUris(
    val redirectUris: Set<String>,
    val ttlSeconds: Long?
)