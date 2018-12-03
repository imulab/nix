package io.imulab.nix.server.config

import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import kotlinx.coroutines.runBlocking
import org.jose4j.jwk.JsonWebKeySet
import org.springframework.beans.factory.InitializingBean
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.time.Duration

@Configuration
@ConfigurationProperties(prefix = "nix")
class NixProperties(
    private val jwksRepo: JsonWebKeySetRepository
) : OidcContext, InitializingBean {

    val endpoints = EndpointConfig()
    val oauth = OAuthConfig()
    val oidc = OidcConfig()
    val security = SecurityConfig()
    val authorizeCode = AuthorizeCodeConfig()
    val accessToken = AccessTokenConfig()
    val refreshToken = RefreshTokenConfig()
    val loginToken = LoginTokenConfig()
    val consentToken = ConsentTokenConfig()
    val idToken = IdTokenConfig()
    val userInfo = UserInfoConfig()
    val requestObject = RequestObjectConfig()
    val claims = ClaimConfig()

    class EndpointConfig(
        var issuer: String = "",
        var jwks: String = "",
        var authorize: String = "",
        var token: String = "",
        var userInfo: String = "",
        var registration: String = "",
        var login: String = "",
        var consent: String = ""
    )

    class OAuthConfig(
        var stateEntropy: Int = 0,
        var scopes: List<String> = emptyList(),
        var responseTypes: List<String> = emptyList()
    )

    class OidcConfig(
        var nonceEntropy: Int = 0,
        var acrValues: List<String> = emptyList(),
        var subjectTypes: List<String> = emptyList(),
        var responseModes: List<String> = emptyList(),
        var display: List<String> = emptyList(),
        var uiLocales: List<String> = emptyList(),
        var serviceDoc: String = "",
        var policyUri: String = ""
    )

    class SecurityConfig(
        var subjectSalt: String = "",
        val tokenEndpointAuth: TokenEndpointAuthConfig = TokenEndpointAuthConfig()
    ) {
        class TokenEndpointAuthConfig(
            var default: String = "",
            var supported: List<String> = emptyList(),
            var signatureAlgorithms: List<String> = emptyList()
        )
    }

    class AuthorizeCodeConfig(var expiration: Duration = Duration.ZERO)
    class AccessTokenConfig(var expiration: Duration = Duration.ZERO)
    class RefreshTokenConfig(var expiration: Duration = Duration.ZERO)
    class LoginTokenConfig(var expiration: Duration = Duration.ZERO)
    class ConsentTokenConfig(var expiration: Duration = Duration.ZERO)

    class IdTokenConfig(
        var expiration: Duration = Duration.ZERO,
        var signingAlgorithms: List<String> = emptyList(),
        var encryptionAlgorithms: List<String> = emptyList(),
        var encryptionEncodings: List<String> = emptyList()
    )

    class UserInfoConfig(
        var signingAlgorithms: List<String> = emptyList(),
        var encryptionAlgorithms: List<String> = emptyList(),
        var encryptionEncodings: List<String> = emptyList()
    )

    class RequestObjectConfig(
        var signingAlgorithms: List<String> = emptyList(),
        var encryptionAlgorithms: List<String> = emptyList(),
        var encryptionEncodings: List<String> = emptyList(),
        var supportRequestParameter: Boolean = false,
        var supportRequestUriParameter: Boolean = false,
        var requireRequestUriRegistration: Boolean = false
    )

    class ClaimConfig(
        var supported: Boolean = false,
        var values: List<String> = emptyList(),
        var types: List<String> = emptyList(),
        var locales: List<String> = emptyList()
    )

    override val idTokenLifespan: Duration
        get() = idToken.expiration
    override val masterJsonWebKeySet: JsonWebKeySet
        get() = runBlocking { jwksRepo.getServerJsonWebKeySet() }
    override val nonceEntropy: Int
        get() = oidc.nonceEntropy
    override val issuerUrl: String
        get() = endpoints.issuer
    override val authorizeEndpointUrl: String
        get() = endpoints.authorize
    override val tokenEndpointUrl: String
        get() = endpoints.token
    override val defaultTokenEndpointAuthenticationMethod: String
        get() = security.tokenEndpointAuth.default
    override val authorizeCodeLifespan: Duration
        get() = authorizeCode.expiration
    override val accessTokenLifespan: Duration
        get() = accessToken.expiration
    override val refreshTokenLifespan: Duration
        get() = refreshToken.expiration
    override val stateEntropy: Int
        get() = oauth.stateEntropy
    override val issuer: String
        get() = endpoints.issuer
    override val authorizationEndpoint: String
        get() = endpoints.authorize
    override val tokenEndpoint: String
        get() = endpoints.token
    override val userInfoEndpoint: String
        get() = endpoints.userInfo
    override val jwksUri: String
        get() = endpoints.jwks
    override val registrationEndpoint: String
        get() = endpoints.registration
    override val scopesSupported: List<String>
        get() = oauth.scopes
    override val responseTypesSupported: List<String>
        get() = oauth.responseTypes
    override val acrValuesSupported: List<String>
        get() = oidc.acrValues
    override val subjectTypesSupported: List<String>
        get() = oidc.subjectTypes
    override val idTokenSigningAlgorithmValuesSupported: List<String>
        get() = idToken.signingAlgorithms
    override val idTokenEncryptionAlgorithmValuesSupported: List<String>
        get() = idToken.encryptionAlgorithms
    override val idTokenEncryptionEncodingValuesSupported: List<String>
        get() = idToken.encryptionEncodings
    override val userInfoSigningAlgorithmValuesSupported: List<String>
        get() = userInfo.signingAlgorithms
    override val userInfoEncryptionAlgorithmValuesSupported: List<String>
        get() = userInfo.encryptionAlgorithms
    override val userInfoEncryptionEncodingValuesSupported: List<String>
        get() = userInfo.encryptionEncodings
    override val requestObjectSigningAlgorithmValuesSupported: List<String>
        get() = requestObject.signingAlgorithms
    override val requestObjectEncryptionAlgorithmValuesSupported: List<String>
        get() = requestObject.encryptionAlgorithms
    override val requestObjectEncryptionEncodingValuesSupported: List<String>
        get() = requestObject.encryptionEncodings
    override val tokenEndpointAuthenticationSigningAlgorithmValuesSupported: List<String>
        get() = security.tokenEndpointAuth.signatureAlgorithms
    override val displayValuesSupported: List<String>
        get() = oidc.display
    override val claimsSupported: List<String>
        get() = claims.values
    override val serviceDocumentation: String
        get() = oidc.serviceDoc
    override val claimsLocalesSupported: List<String>
        get() = claims.locales
    override val uiLocalesSupported: List<String>
        get() = oidc.uiLocales
    override val opPolicyUri: String
        get() = oidc.policyUri

    override fun afterPropertiesSet() {
        validate()
    }
}