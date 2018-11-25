package io.imulab.nix.oauth.client

/**
 * Provides client lookup functions
 */
interface ClientLookup {

    /**
     * Attempt to find the client by its [identifier]. If client
     * is not found, raise invalid_client (unknown) error.
     */
    suspend fun find(identifier: String): OAuthClient
}