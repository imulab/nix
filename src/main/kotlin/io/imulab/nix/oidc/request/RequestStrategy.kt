package io.imulab.nix.oidc.request

import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oidc.reserved.JweContentEncodingAlgorithm
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.error.InvalidRequestObject
import io.imulab.nix.oidc.error.InvalidRequestUri
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.jwk.JwtVerificationKeyResolver
import io.imulab.nix.oidc.jwk.mustKeyForJweKeyManagement
import io.imulab.nix.oidc.jwk.resolvePrivateKey
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.call.receive
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.OctetSequenceJsonWebKey
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey
import java.security.MessageDigest
import java.time.Duration
import java.time.LocalDateTime
import java.util.*

/**
 * General logic to resolve a request object
 *
 * When request object is provided through the `request` parameter, it is adopted
 * directly.
 *
 * When request object is provided by reference through the `request_uri` parameter, this strategy
 * checks if it matches any pre-registered values at [OidcClient.requestUris]. If it was registered, an
 * attempt is made to find the request object from cache and compare its hash values to ensure it is the
 * intended version. If it wasn't registered, an attempt is made to fetch the request object from the
 * `request_uri`. Upon successful retrieval, hash is calculated and verified and the item is written
 * to cache to avoid roundtrips later.
 *
 * After securing the request object from various sources, this strategy also attempts to decrypt
 * (if [OidcClient.requestObjectEncryptionAlgorithm] is registered) the request object and verify
 * its signature. In the end, if everything goes well, a [JwtClaims] object representing the content
 * of the request object is returned.
 */
class RequestStrategy(
    private val repository: CachedRequestRepository,
    private val httpClient: HttpClient,
    private val jsonWebKeySetStrategy: JsonWebKeySetStrategy,
    private val serverContext: OidcContext,
    private val requestCacheLifespan: Duration? = Duration.ofDays(30)
) {

    private val sha256: MessageDigest = MessageDigest.getInstance("SHA-256")
    private val base64Encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    suspend fun resolveRequest(request: String, requestUri: String, client: OidcClient): JwtClaims = try {
        doResolveRequest(request, requestUri, client)
    } catch (e: Exception) {
        when (e) {
            is OAuthException -> throw e
            else -> throw InvalidRequestObject.invalid()
        }
    }

    private suspend fun doResolveRequest(request: String, requestUri: String, client: OidcClient): JwtClaims {
        if (request.isNotEmpty()) {
            check(requestUri.isEmpty()) {
                "request and request_uri cannot be used at the same time."
            }

            return processRequest(request, client)
        }

        if (requestUri.isNotEmpty()) {
            if (!client.requestUris.contains(requestUri))
                throw InvalidRequestUri.rouge()
            else if (requestUri.length > 512)
                throw InvalidRequestUri.tooLong()

            val cachedRequest = fetchFromRepository(requestUri)
            if (cachedRequest != null)
                return processRequest(request = cachedRequest, client = client)

            return processRequest(
                request = fetchFromRemote(requestUri, client),
                client = client
            )
        }

        return JwtClaims()
    }

    private suspend fun fetchFromRepository(requestUri: String): String? {
        // sanitize request_uri, separate fragment if any
        val fragment = Url(requestUri).fragment
        val cacheId = if (fragment.isEmpty()) requestUri else {
            URLBuilder(requestUri).also {
                it.fragment = ""
            }.buildString()
        }

        val cached = repository.find(cacheId) ?: return null

        if (cached.hasExpired()) {
            withContext(Dispatchers.IO) {
                launch { repository.evict(cacheId) }
            }
            return null
        }

        if (fragment.isNotEmpty() && !fragment.equals(cached.hash, ignoreCase = true)) {
            withContext(Dispatchers.IO) {
                launch { repository.evict(cacheId) }
            }
            return null
        }

        return cached.request
    }

    private suspend fun fetchFromRemote(requestUri: String, client: OidcClient): String {
        val request = withContext(Dispatchers.IO) {
            run {
                httpClient.call(requestUri).response.let { httpResponse ->
                    when (httpResponse.status) {
                        HttpStatusCode.OK -> httpResponse.receive<String>()
                        else -> throw InvalidRequestUri.none200(httpResponse.status.value)
                    }
                }
            }
        }

        if (request.isEmpty())
            throw InvalidRequestUri.invalid()

        val fragment = Url(requestUri).fragment
        val cacheId = if (fragment.isEmpty()) requestUri else {
            URLBuilder(requestUri).also {
                it.fragment = ""
            }.buildString()
        }

        val hash = base64Encoder.encodeToString(sha256.digest(request.toByteArray()))
        if (fragment.isNotEmpty() && !fragment.equals(hash, ignoreCase = true))
            throw InvalidRequestUri.badHash()

        withContext(Dispatchers.IO) {
            launch {
                repository.write(
                    CachedRequest(
                        requestUri = cacheId,
                        request = request,
                        hash = hash,
                        expiry = if (requestCacheLifespan == null) null else
                            LocalDateTime.now().plus(requestCacheLifespan)
                    )
                )
            }
        }

        return request
    }

    private suspend fun processRequest(request: String, client: OidcClient): JwtClaims =
        verifySignature(
            request = decryptRequest(request, client),
            client = client
        )

    private fun decryptRequest(request: String, client: OidcClient): String {
        if (!client.requireRequestObjectEncryption())
            return request

        check(client.requestObjectEncryptionAlgorithm != JweKeyManagementAlgorithm.None) {
            "Client requesting encryption must not specify none as key management algorithm"
        }
        check(client.requestObjectEncryptionEncoding != JweContentEncodingAlgorithm.None) {
            "Client requesting encryption must not specify none as content encoding algorithm"
        }

        val jwk = client.requestObjectEncryptionAlgorithm.let { alg ->
            if (alg.isSymmetric)
                OctetSequenceJsonWebKey(AesKey(client.secret))
            else
                serverContext.masterJsonWebKeySet.mustKeyForJweKeyManagement(alg)
        }

        return JsonWebEncryption().also {
            it.setAlgorithmConstraints(client.requestObjectEncryptionAlgorithm.whitelisted())
            it.setContentEncryptionAlgorithmConstraints(client.requestObjectEncryptionEncoding.whitelisted())
            it.compactSerialization = request
            it.key = jwk.resolvePrivateKey()
        }.plaintextString
    }

    private suspend fun verifySignature(request: String, client: OidcClient): JwtClaims {
        return when (client.requestObjectSigningAlgorithm) {
            JwtSigningAlgorithm.None -> {
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setJwsAlgorithmConstraints(client.requestObjectSigningAlgorithm.whitelisted())
                    .setSkipVerificationKeyResolutionOnNone()
                    .setDisableRequireSignature()
                    .setExpectedAudience(serverContext.issuerUrl)
                    .build()
                    .processToClaims(request)
            }
            else -> {
                val jwks = jsonWebKeySetStrategy.resolveKeySet(client)
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setJwsAlgorithmConstraints(client.requestObjectSigningAlgorithm.whitelisted())
                    .setVerificationKeyResolver(
                        JwtVerificationKeyResolver(jwks, client.requestObjectSigningAlgorithm)
                    )
                    .setExpectedIssuer(null)
                    .setExpectedAudience(serverContext.issuerUrl)
                    .build()
                    .processToClaims(request)
            }
        }
    }
}