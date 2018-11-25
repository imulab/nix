package deprecated.client.sector.strategy

import deprecated.client.OidcClient
import deprecated.client.sector.RemoteRedirectUris

interface SectorIdentifierStrategy {

    suspend fun getRedirectUris(client: OidcClient): RemoteRedirectUris
}