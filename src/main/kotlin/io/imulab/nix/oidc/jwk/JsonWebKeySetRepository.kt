package io.imulab.nix.oidc.jwk

import org.jose4j.jwk.JsonWebKeySet

/**
 * Data management interface for saved Json Web Key Sets.
 */
interface JsonWebKeySetRepository {

    /**
     * Returns the special json web key set belongs to the server
     */
    suspend fun getServerJsonWebKeySet(): JsonWebKeySet

    /**
     * Returns the json web key set identifiable by the [jwksUri]
     */
    suspend fun getClientJsonWebKeySet(jwksUri: String): JsonWebKeySet?

    /**
     * Associate the [keySet] with the [jwksUri] and write to the repository
     */
    suspend fun writeClientJsonWebKeySet(jwksUri: String, keySet: JsonWebKeySet)
}