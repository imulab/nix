package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthAuthorizeRequest
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.OAuthSession
import io.imulab.nix.oidc.client.OidcClient
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
 * Extension to [OAuthRequestForm] to provide access to Open ID Connect specified parameters.
 */
class OidcRequestForm(httpForm: MutableMap<String, List<String>>) : OAuthRequestForm(
    httpForm, mapOf(
        "responseMode" to OidcParam.responseMode,
        "nonce" to OidcParam.nonce,
        "display" to OidcParam.display,
        "prompt" to OidcParam.prompt,
        "maxAge" to OidcParam.maxAge,
        "uiLocales" to OidcParam.uiLocales,
        "idTokenHint" to OidcParam.idTokenHint,
        "loginHint" to OidcParam.loginHint,
        "acrValues" to OidcParam.acrValues,
        "claims" to OidcParam.claims,
        "claimsLocales" to OidcParam.claimsLocales,
        "request" to OidcParam.request,
        "requestUri" to OidcParam.requestUri,
        "registration" to OidcParam.registration,
        "iss" to OidcParam.iss,
        "targetLinkUri" to OidcParam.targetLinkUri
    )
) {
    var responseMode: String by Delegate
    var nonce: String by Delegate
    var display: String by Delegate
    var prompt: String by Delegate
    var maxAge: String by Delegate
    var uiLocales: String by Delegate
    var idTokenHint: String by Delegate
    var loginHint: String by Delegate
    var acrValues: String by Delegate
    var claims: String by Delegate
    var claimsLocales: String by Delegate
    var request: String by Delegate
    var requestUri: String by Delegate
    var registration: String by Delegate
    var iss: String by Delegate
    var targetLinkUri: String by Delegate
}

/**
 * An Open ID Connect Authorize Request.
 */
class OidcAuthorizeRequest(
    client: OidcClient,
    responseTypes: Set<String>,
    redirectUri: String,
    scopes: Set<String>,
    state: String,
    val responseMode: String?,
    val nonce: String?,
    val display: String?,
    val prompts: Set<String>,
    val maxAge: Long?,
    val uiLocales: List<String>,
    val idTokenHint: String?,
    val loginHint: String?,
    val acrValues: List<String>,
    val claims: Claims,
    val claimsLocales: List<String>,
    session: OidcSession = OidcSession()
) : OAuthAuthorizeRequest(
    client = client,
    responseTypes = responseTypes,
    redirectUri = redirectUri,
    scopes = scopes,
    state = state,
    session = session
)

/**
 * Open ID Connect User Session.
 */
class OidcSession(
    subject: String = "",
    val claims: MutableMap<String, Any> = mutableMapOf()
) : OAuthSession(subject)

/**
 * Data object of a server cached request object. This can be created when client
 * registers a set of request_uris as well as when server actively fetches content
 * from a request_uri during request.
 */
class CachedRequest(

    /**
     * Original request_uri parameter used to fetch this request, less any fragment component.
     */
    val requestUri: String,

    /**
     * Fetched request object.
     */
    val request: String,

    /**
     * When this cached request expire.
     */
    val expiry: LocalDateTime? = null,

    /**
     * Computed SHA-256 hash of the [request].
     */
    val hash: String = ""
) {
    fun hasExpired(): Boolean = expiry?.isAfter(LocalDateTime.now()) == true
}

/**
 * Data management interface for a [CachedRequest].
 */
interface CachedRequestRepository {

    /**
     * Write a [request] to cache. Implementations may expect [CachedRequest.expiry] if
     * it is set.
     */
    suspend fun write(request: CachedRequest)

    /**
     * Find if a [CachedRequest] was cached with [requestUri].
     *
     * @param requestUri the unmodified version of the request_uri parameter, including
     * scheme, host and fragment (if any).
     */
    suspend fun find(requestUri: String): CachedRequest?

    /**
     * Remove the cached entry associated with [requestUri].
     */
    suspend fun evict(requestUri: String)
}

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