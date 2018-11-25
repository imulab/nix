package io.imulab.nix.oauth

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

        "authorizationHeader" to Header.authorization
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