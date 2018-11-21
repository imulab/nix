package io.imulab.nix.client.sector.strategy

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.sector.RemoteRedirectUris

class CacheStrategy(private val fetchStrategy: FetchStrategy): SectorIdentifierStrategy {

    override suspend fun getRedirectUris(client: OidcClient): RemoteRedirectUris {
        val redirectUris = fetchStrategy.getRedirectUris(client)
        println("faked caching of ${redirectUris.redirectUris}")
        return redirectUris
    }
}