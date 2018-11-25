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
open class OAuthRequestForm(val httpForm: MutableMap<String, List<String>>) {

    var clientId: String by Delegate
    var clientSecret: String by Delegate
    var scope: String by Delegate
    val redirectUri: String by Delegate
    val responseType: String by Delegate
    val state: String by Delegate
    val code: String by Delegate
    val grantType: String by Delegate
    val username: String by Delegate
    val password: String by Delegate

    protected val mapping by lazy {
        mapOf(
            "clientId" to Param.clientId,
            "clientSecret" to Param.clientSecret,
            "scope" to Param.scope,
            "redirectUri" to Param.redirectUri,
            "responseType" to Param.responseType,
            "state" to Param.state,
            "code" to Param.code,
            "grantType" to Param.grantType,
            "username" to Param.username,
            "password" to Param.password
        )
    }

    protected object Delegate {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
            val ref = thisRef as OAuthRequestForm
            return ref.httpForm.singleOrNull(ref.mapping[property.name]!!) ?: ""
        }

        operator fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
            val ref = thisRef as OAuthRequestForm
            ref.httpForm[ref.mapping[property.name]!!] = listOf(value)
        }
    }
}