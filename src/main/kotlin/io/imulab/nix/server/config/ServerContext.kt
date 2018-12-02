package io.imulab.nix.server.config

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.server.*
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import kotlinx.coroutines.runBlocking
import org.jose4j.jwk.JsonWebKeySet
import java.time.Duration
import kotlin.reflect.KProperty

/**
 * Global server configuration
 */
@UseExperimental(KtorExperimentalAPI::class)
class ServerContext(
    private val config: ApplicationConfig,
    private val jsonWebKeySetRepository: JsonWebKeySetRepository
) : OidcContext {

    override val masterJsonWebKeySet: JsonWebKeySet by lazy {
        runBlocking { jsonWebKeySetRepository.getServerJsonWebKeySet() }
    }

    override val issuer: String
        get() = issuerUrl

    override val tokenEndpoint: String
        get() = tokenEndpointUrl

    override val authorizationEndpoint: String
        get() = authorizeEndpointUrl

    //region endpoints
    override val issuerUrl: String by S("nix.endpoint.issuer")
    override val authorizeEndpointUrl: String by S("nix.endpoint.authorize")
    override val tokenEndpointUrl: String by S("nix.endpoint.token")
    override val userInfoEndpoint: String by S("nix.endpoint.userinfo")
    override val jwksUri: String by S("nix.endpoint.jwks")
    override val registrationEndpoint: String by S("nix.endpoint.registration")
    val loginProviderEndpoint: String by S("nix.endpoint.login")
    val consentProviderEndpoint: String by S("nix.endpoint.consent")
    //endregion

    //region Token endpoint authentication
    override val defaultTokenEndpointAuthenticationMethod: String
            by S("nix.security.tokenEndpointAuth.default")
    override val tokenEndpointAuthenticationMethodsSupported: List<String>
            by L(
                "nix.security.tokenEndpointAuth.supported",
                super.tokenEndpointAuthenticationMethodsSupported
            )
    override val tokenEndpointAuthenticationSigningAlgorithmValuesSupported: List<String>
            by L("nix.security.tokenEndpointAuth.signatureAlgorithms")
    //endregion

    //region Code and tokens
    override val authorizeCodeLifespan: Duration by D(
        "nix.authorizeCode.expirationSeconds",
        Duration.ofMinutes(10)
    )
    override val accessTokenLifespan: Duration by D(
        "nix.accessToken.expirationSeconds",
        Duration.ofDays(1)
    )
    override val refreshTokenLifespan: Duration by D(
        "nix.refreshToken.expirationSeconds",
        Duration.ofDays(14)
    )
    override val idTokenLifespan: Duration by D(
        "nix.idToken.expirationSeconds",
        Duration.ofDays(1)
    )
    override val idTokenSigningAlgorithmValuesSupported: List<String> by L("nix.idToken.signingAlgorithms")
    override val idTokenEncryptionAlgorithmValuesSupported: List<String> by L(
        "nix.idToken.encryptionAlgorithms"
    )
    override val idTokenEncryptionEncodingValuesSupported: List<String> by L("nix.idToken.encryptionEncodings")
    val loginTokenLifespan: Duration by D(
        "nix.loginToken.expirationSeconds",
        Duration.ofMinutes(10)
    )
    val consentTokenLifespan: Duration by D(
        "nix.consentToken.expirationSeconds",
        Duration.ofMinutes(10)
    )
    //endregion

    //region User info
    override val userInfoSigningAlgorithmValuesSupported: List<String> by L("nix.userInfo.signingAlgorithms")
    override val userInfoEncryptionAlgorithmValuesSupported: List<String> by L(
        "nix.userInfo.encryptionAlgorithms"
    )
    override val userInfoEncryptionEncodingValuesSupported: List<String> by L(
        "nix.userInfo.encryptionEncodings"
    )
    //endregion

    //region Request object
    override val requestObjectSigningAlgorithmValuesSupported: List<String>
            by L("nix.requestObject.signingAlgorithms")
    override val requestObjectEncryptionAlgorithmValuesSupported: List<String>
            by L("nix.requestObject.encryptionAlgorithms")
    override val requestObjectEncryptionEncodingValuesSupported: List<String>
            by L("nix.requestObject.encryptionEncodings")
    override val requestParameterSupported: Boolean
            by B(
                "nix.requestObject.supportRequestParameter",
                super.requestParameterSupported
            )
    override val requestUriParameterSupported: Boolean
            by B(
                "nix.requestObject.supportRequestUriParameter",
                super.requestUriParameterSupported
            )
    override val requireRequestUriRegistration: Boolean
            by B(
                "nix.requestObject.requireRequestUriRegistration",
                super.requireRequestUriRegistration
            )
    //endregion

    //region Claims
    override val claimsParameterSupported: Boolean by B("nix.claims.supported")
    override val claimsSupported: List<String> by L("nix.claims.values")
    override val claimValuesSupported: List<String> by L("nix.claims.types")
    override val claimsLocalesSupported: List<String> by L("nix.claims.locales")
    //endregion

    //region OAuth
    override val stateEntropy: Int by I("nix.oauth.stateEntropy")
    override val scopesSupported: List<String> by L("nix.oauth.scopes")
    override val responseTypesSupported: List<String> by L("nix.oauth.responseTypes")
    override val grantTypesSupported: List<String> by L("nix.oauth.grantTypes")
    //endregion

    //region OIDC
    override val nonceEntropy: Int by I("nix.oidc.nonceEntropy")
    override val acrValuesSupported: List<String> by L("nix.oidc.acrValues")
    override val subjectTypesSupported: List<String> by L("nix.oidc.subjectTypes")
    override val displayValuesSupported: List<String> by L("nix.oidc.display")
    override val serviceDocumentation: String by S("nix.oidc.serviceDoc")
    override val uiLocalesSupported: List<String> by L("nix.oidc.uiLocales")
    override val opPolicyUri: String by S("nix.oidc.policyUri")
    override val responseModeSupported: List<String> by L("nix.oidc.responseModes")
    //endregion

    private class S(val propertyName: String, val default: String? = null) {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
            return thisRef.assertType<ServerContext>().config.stringPropertyOrNull(propertyName) ?: default ?: ""
        }
    }

    private class L(val propertyName: String, val default: List<String>? = null) {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): List<String> {
            return thisRef.assertType<ServerContext>().config.stringListPropertyOrNull(propertyName) ?: default ?: emptyList()
        }
    }

    private class D(val propertyName: String, val default: Duration? = null) {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): Duration {
            return thisRef.assertType<ServerContext>().config.longPropertyOrNull(propertyName)
                ?.let { Duration.ofSeconds(it) } ?: default ?: Duration.ZERO
        }
    }

    private class B(val propertyName: String, val default: Boolean = false) {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): Boolean {
            return thisRef.assertType<ServerContext>().config.booleanPropertyOrNull(propertyName) ?: default
        }
    }

    private class I(val propertyName: String, val default: Int = 0) {
        operator fun getValue(thisRef: Any?, property: KProperty<*>): Int {
            return thisRef.assertType<ServerContext>().config.intPropertyOrNull(propertyName) ?: default
        }
    }
}