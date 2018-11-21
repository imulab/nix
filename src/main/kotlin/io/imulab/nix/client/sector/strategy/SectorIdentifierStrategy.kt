package io.imulab.nix.client.sector.strategy

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.sector.RemoteRedirectUris

interface SectorIdentifierStrategy {

    suspend fun getRedirectUris(client: OidcClient): RemoteRedirectUris
}