package deprecated.client.sector.strategy

import deprecated.client.OidcClient
import deprecated.client.sector.RemoteRedirectUris

class CacheStrategy(private val fetchStrategy: FetchStrategy):
    SectorIdentifierStrategy {

    override suspend fun getRedirectUris(client: OidcClient): RemoteRedirectUris {
        val redirectUris = fetchStrategy.getRedirectUris(client)
        println("faked caching of ${redirectUris.redirectUris}")
        return redirectUris
    }
}