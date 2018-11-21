package io.imulab.nix.client.manager

import io.imulab.nix.client.OAuthClient

interface ClientStore {

    suspend fun getClient(id: String): OAuthClient
}