package io.imulab.nix.oauth

import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import java.time.LocalDateTime
import java.util.*
import kotlin.reflect.KProperty

/**
 * Adapter class to bridge from a map based http form that was read from the http request
 * to a type safe request form for processing. This class exposes all request parameters
 * as plain strings. Downstream processors may elect to parse them into the desired type.
 *
 * This class also achieves the effect that, according to OAuth 2.0 Spec, unknown request
 * parameters are discarded.
 *
 * This class should only be used to access request parameters briefly, and not used for
 * all downstream processing because its property is backed by a map, which could be
 * slow to access.
 *
 * Possible usage scenarios include (but not restricted to) consolidating request parameter
 * values from multiple sources. For instance, resolving OIDC request object.
 */
open class OAuthRequestForm(
    val httpForm: MutableMap<String, List<String>>,
    additionalMapping: Map<String, String> = emptyMap()
) {

    private val mapping = mutableMapOf(
        "clientId" to Param.clientId,
        "clientSecret" to Param.clientSecret,
        "scope" to Param.scope,
        "redirectUri" to Param.redirectUri,
        "responseType" to Param.responseType,
        "state" to Param.state,
        "code" to Param.code,
        "grantType" to Param.grantType,
        "username" to Param.username,
        "password" to Param.password,
        "authorizationHeader" to Header.authorization,
        "loginToken" to Param.Internal.loginToken,
        "consentToken" to Param.Internal.consentToken
    )

    init {
        mapping.putAll(additionalMapping)
    }

    var clientId: String by Delegate
    var clientSecret: String by Delegate
    var scope: String by Delegate
    var redirectUri: String by Delegate
    var responseType: String by Delegate
    var state: String by Delegate
    var code: String by Delegate
    var grantType: String by Delegate
    var username: String by Delegate
    var password: String by Delegate

    var authorizationHeader: String by Delegate

    var loginToken: String by Delegate
    var consentToken: String by Delegate

    protected object Delegate {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
            val ref = thisRef as OAuthRequestForm
            checkNotNull(ref.mapping[property.name]) {
                "unregistered property mapping"
            }
            return ref.httpForm.singleOrNull(ref.mapping[property.name]!!) ?: ""
        }

        operator fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
            val ref = thisRef as OAuthRequestForm
            checkNotNull(ref.mapping[property.name]) {
                "unregistered property mapping"
            }
            ref.httpForm[ref.mapping[property.name]!!] = listOf(value)
        }
    }
}

/**
 * Super class of all OAuth requests.
 */
open class OAuthRequest(
    val id: String = UUID.randomUUID().toString(),
    val requestTime: LocalDateTime = LocalDateTime.now(),
    val client: OAuthClient,
    val session: OAuthSession = OAuthSession()
)

/**
 * An OAuth authorize request
 */
open class OAuthAuthorizeRequest(
    client: OAuthClient,
    val responseTypes: Set<String>,
    val redirectUri: String,
    val scopes: Set<String>,
    val state: String,
    val grantedScopes: MutableSet<String> = mutableSetOf(),
    session: OAuthSession = OAuthSession()
) : OAuthRequest(client = client, session = session) {

    /**
     * Convenience method to grant a scope. The granted scope must be in the requested [scopes].
     */
    fun grantScope(scope: String) {
        if (scopes.contains(scope))
            grantedScopes.add(scope)
    }

    class Builder(
        var responseTypes: MutableSet<String> = mutableSetOf(),
        var redirectUri: String = "",
        var scopes: MutableSet<String> = mutableSetOf(),
        var state: String = "",
        var client: OAuthClient? = null
    ) {

        fun build(): OAuthAuthorizeRequest {
            if (responseTypes.isEmpty())
                throw InvalidRequest.required(Param.responseType)

            check(redirectUri.isNotEmpty())
            checkNotNull(client)

            return OAuthAuthorizeRequest(
                client = client!!,
                responseTypes = responseTypes.toSet(),
                redirectUri = redirectUri,
                scopes = scopes,
                state = state
            )
        }
    }
}

/**
 * An OAuth access request
 */
open class OAuthAccessRequest(
    val grantTypes: Set<String>,
    val code: String,
    val redirectUri: String,
    client: OAuthClient
) : OAuthRequest(client = client) {

    class Builder(
        var grantTypes: MutableSet<String> = mutableSetOf(),
        var code: String = "",
        var redirectUri: String = "",
        var client: OAuthClient? = null
    ) {

        fun build(): OAuthAccessRequest {
            if (grantTypes.isEmpty())
                throw InvalidRequest.required(Param.grantType)
            if (code.isEmpty())
                throw InvalidRequest.required(Param.code)
            if (redirectUri.isEmpty())
                throw InvalidRequest.required(Param.redirectUri)

            checkNotNull(client)

            return OAuthAccessRequest(
                grantTypes = grantTypes.toSet(),
                code = code,
                redirectUri = redirectUri,
                client = client!!
            )
        }
    }
}

open class OAuthSession(
    var subject: String = "",
    var originalRequestTime: LocalDateTime? = null
)

/**
 * Provides function to take [OAuthRequestForm] and produce a [OAuthRequest]. Subclasses can call
 * super producers to get a prototype request object and then supply data to its own builder.
 */
interface OAuthRequestProducer {
    suspend fun produce(form: OAuthRequestForm): OAuthRequest
}

/**
 * Implementation of [OAuthRequestProducer] that takes the input parameter values from [OAuthRequestForm]
 * and populates [OAuthAuthorizeRequest]. This producer also performs some light value based validation
 * to ensure at least specification values are respected. Further validation needs to be performed by
 * validators.
 */
open class OAuthAuthorizeRequestProducer(
    private val lookup: ClientLookup,
    private val responseTypeValidator: SpecDefinitionValidator
) : OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        if (form.clientId.isEmpty())
            throw InvalidRequest.required(Param.clientId)

        val client = lookup.find(form.clientId)

        val builder = OAuthAuthorizeRequest.Builder().also { b ->
            b.client = client
            b.redirectUri = client.determineRedirectUri(form.redirectUri)
            b.responseTypes = form.responseType
                .split(space)
                .filter { it.isNotBlank() }
                .toMutableSet()
            b.state = form.state
            b.scopes = form.scope
                .split(space)
                .filter { it.isNotBlank() }
                .toMutableSet()
        }

        return builder.build()
    }
}

/**
 * Implementation of [OAuthRequestProducer] that takes the input parameter values from [OAuthRequestForm]
 * and populates [OAuthAccessRequest].
 *
 * This producer is responsible for authenticating the client using [ClientAuthenticators].
 *
 * This producer also performs some light value based validation to ensure at least specification values
 * are respected. Further validation needs to be performed by validators.
 */
open class OAuthAccessRequestProducer(
    private val grantTypeValidator: SpecDefinitionValidator,
    private val clientAuthenticators: ClientAuthenticators
) : OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        if (form.clientId.isEmpty())
            throw InvalidRequest.required(Param.clientId)

        val client = clientAuthenticators.authenticate(form)

        val builder = OAuthAccessRequest.Builder().also { b ->
            b.client = client
            b.code = form.code
            b.grantTypes = form.grantType
                .split(space)
                .filter { it.isNotBlank() }
                .map { grantTypeValidator.validate(it) }
                .toMutableSet()
            b.redirectUri = form.redirectUri
        }

        return builder.build()
    }
}