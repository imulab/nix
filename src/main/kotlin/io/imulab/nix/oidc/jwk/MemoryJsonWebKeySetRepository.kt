package io.imulab.nix.oidc.jwk

import org.jose4j.jwk.JsonWebKeySet

/**
 * Memory implementation of [JsonWebKeySetRepository].
 */
class MemoryJsonWebKeySetRepository(private val serverJwks: JsonWebKeySet) : JsonWebKeySetRepository {

    private val database = mutableMapOf<String, JsonWebKeySet>()

    override suspend fun getServerJsonWebKeySet(): JsonWebKeySet = serverJwks

    override suspend fun getClientJsonWebKeySet(jwksUri: String): JsonWebKeySet? = database[jwksUri]

    override suspend fun writeClientJsonWebKeySet(jwksUri: String, keySet: JsonWebKeySet) {
        database[jwksUri] = keySet
    }
}