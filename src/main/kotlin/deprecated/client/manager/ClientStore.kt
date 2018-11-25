package deprecated.client.manager

import deprecated.client.OAuthClient

interface ClientStore {

    suspend fun getClient(id: String): OAuthClient
}