package io.imulab.nix.oidc.jwk

import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.spi.SimpleHttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.lang.JoseException

/**
 * Logic to resolve a Json Web Key Set for client via its registered jwks_uri and jwks parameter:
 *
 * When both parameter is empty, it returns an empty [JsonWebKeySet]. When both parameter is specified,
 * it raises server_error.
 *
 * If [OidcClient.jwks] is not empty, it parses it into [JsonWebKeySet] and returns.
 *
 * If [OidcClient.jwksUri] is not empty, it first tries to find a saved key set from [jsonWebKeySetRepository]. If no
 * avail, it will try to fetch it from this uri, parse the response content, save it and return it.
 *
 * Note that this strategy DOES NOT take care of removing the old jwks cache in the case of client updating the
 * registered jwks_uri value. Client registration process must tend to that.
 */
class JsonWebKeySetStrategy(
    private val jsonWebKeySetRepository: JsonWebKeySetRepository,
    private val httpClient: SimpleHttpClient
) {

    suspend fun resolveKeySet(client: OidcClient): JsonWebKeySet = try {
        doResolveKeySet(client)
    } catch (e: JoseException) {
        throw ServerError.internal("Invalid json web key set.")
    }

    private suspend fun doResolveKeySet(client: OidcClient): JsonWebKeySet {
        if (client.jwks.isNotEmpty()) {
            check(client.jwksUri.isEmpty()) {
                """
                    Client jwks and jwks_uri cannot be both registered.
                    If jwks_uri can be used, client must not use jwks.
                """.trimIndent()
            }

            return JsonWebKeySet(client.jwks)
        }

        if (client.jwksUri.isNotEmpty()) {
            val saved = jsonWebKeySetRepository.getClientJsonWebKeySet(client.jwksUri)
            if (saved != null)
                return saved
            return fetchFromRemote(client.jwksUri)
        }

        return JsonWebKeySet()
    }

    private suspend fun fetchFromRemote(jwksUri: String): JsonWebKeySet =
        withContext(Dispatchers.IO) {
            run {
                httpClient.get(jwksUri).let { httpResponse ->
                    when (httpResponse.status()) {
                        200 -> {
                            JsonWebKeySet(httpResponse.body()).also {
                                launch {
                                    jsonWebKeySetRepository.writeClientJsonWebKeySet(
                                        jwksUri = jwksUri,
                                        keySet = it
                                    )
                                }
                            }
                        }
                        else -> throw ServerError.internal("call to jwks_uri returned ${httpResponse.status()}.")
                    }
                }
            }
        }
}