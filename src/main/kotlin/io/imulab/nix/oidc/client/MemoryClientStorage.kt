package io.imulab.nix.oidc.client

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.InvalidClient

/**
 * Memory implementation of [ClientLookup].
 */
class MemoryClientStorage(private val database: MutableMap<String, OidcClient> = mutableMapOf()) : ClientLookup {

    override suspend fun find(identifier: String): OAuthClient =
            database[identifier] ?: throw InvalidClient.unknown()
}