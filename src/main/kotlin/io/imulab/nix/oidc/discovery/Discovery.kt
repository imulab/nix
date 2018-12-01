package io.imulab.nix.oidc.discovery

import io.imulab.nix.oauth.reserved.AuthenticationMethod
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oauth.validation.OAuthGrantTypeValidator
import io.imulab.nix.oidc.reserved.ClaimType
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.oidc.reserved.ResponseMode
import io.imulab.nix.oidc.reserved.StandardScope
import io.imulab.nix.oidc.validation.*

interface Discovery {

    /**
     * REQUIRED. Issuer URL using http scheme with no query or fragment component.
     */
    val issuer: String

    /**
     * REQUIRED. URL for OP's authorization endpoint.
     */
    val authorizationEndpoint: String

    /**
     * REQUIRED unless only implicit flow is used. URL for OP's token endpoint.
     */
    val tokenEndpoint: String

    /**
     * RECOMMENDED. URL for OP's user info endpoint. Must use https scheme and may contain
     * port, path, and query parameter components.
     */
    val userInfoEndpoint: String

    /**
     * REQUIRED. URL to the OP's public json web key set document. It shall contain OP's public
     * key for the RP to verify signature and optionally OP's public key for RP to encrypt
     * documents to be sent to OP. When both signature and encryption key is used, OP shall clearly
     * mark the `use` of the key.
     */
    val jwksUri: String

    /**
     * RECOMMENDED. URL to the OP's dynamic client registration endpoint
     */
    val registrationEndpoint: String

    /**
     * RECOMMENDED. JSON array of scopes supported. Server must support `openid` scope and may choose not
     * to advertise some of the supported scopes.
     */
    val scopesSupported: List<String>

    /**
     * REQUIRED. JSON array of `response_type` supported. Dynamic providers must support `code`, `id_token`,
     * and `token id_token` response type values.
     */
    val responseTypesSupported: List<String>

    /**
     * OPTIONAL. A list of `response_mode` values the OP supports. If omitted, the default values are
     * `query` and `fragment`.
     */
    val responseModeSupported: List<String>
        get() = listOf(ResponseMode.query, ResponseMode.fragment)

    /**
     * OPTIONAL. A list of supported `grant_type`. Dynamic providers must support `authorization_code` and
     * `implicit`. If omitted, the default value is `authorization_code` and `implicit`.
     */
    val grantTypesSupported: List<String>
        get() = listOf(
            GrantType.authorizationCode,
            GrantType.implicit
        )

    /**
     * OPTIONAL. JSON array containing a list of supported authentication context class values.
     */
    val acrValuesSupported: List<String>

    /**
     * REQUIRED. JSON array containing a list of supported subject identifier types. Valid values include
     * `public` and `pairwise`.
     */
    val subjectTypesSupported: List<String>

    /**
     * REQUIRED. List of JWS signing algorithm (`alg` JWT header) supported by OP when signing the id token.
     * The `RS256` algorithm must be supported. The `none` algorithm may be supported, but must not be used
     * unless response type returns no id token from the authorization endpoint.
     */
    val idTokenSigningAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `alg` header) used to encrypt id token.
     */
    val idTokenEncryptionAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `enc` header) used to encrypt id token.
     */
    val idTokenEncryptionEncodingValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWA algorithms used to sign the user info endpoint response.
     * The `none` algorithm may be used.
     */
    val userInfoSigningAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `alg` header) used to encrypt user info.
     */
    val userInfoEncryptionAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `enc` header) used to encrypt user info.
     */
    val userInfoEncryptionEncodingValuesSupported: List<String>

    /**
     * OPTIONAL. List of JWS signing algorithm (`alg` JWT header) supported by OP when signing the request
     * object from both `request` parameter and `request_uri` parameter. Server should support both `none`
     * and `RS256` algorithm.
     */
    val requestObjectSigningAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `alg` header) used to encrypt request
     * object passed both by value and by reference.
     */
    val requestObjectEncryptionAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of JWE algorithms (JWE `enc` header) used to encrypt request
     * object passed both by value and by reference.
     */
    val requestObjectEncryptionEncodingValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of client authentication methods supported by the token
     * endpoint. The option universe if `{client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt}`.
     * If omitted, default value is `client_secret_basic`.
     */
    val tokenEndpointAuthenticationMethodsSupported: List<String>
        get() = listOf(AuthenticationMethod.clientSecretBasic)

    /**
     * OPTIONAL. JSON array of JWS signing algorithm (JWT `alg` header) used when using `private_key_jwt` or
     * `client_secret_jwt` as token endpoint authentication method. Server must support `RS256`. The `none`
     * algorithm must not be used.
     */
    val tokenEndpointAuthenticationSigningAlgorithmValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of supported display parameter values.
     */
    val displayValuesSupported: List<String>

    /**
     * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. The option
     * universe is `normal, aggregated, distributed`. If omitted, the implementation supports only normal Claims.
     */
    val claimValuesSupported: List<String>
        get() = listOf(ClaimType.normal)

    /**
     * RECOMMENDED. JSON array containing a list of the Claim Names that provider may be able to supply values for.
     * Note that for privacy or other reasons, this might not be an exhaustive list.
     */
    val claimsSupported: List<String>

    /**
     * OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when
     * using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration,
     * then information on how to register Clients needs to be provided in this documentation.
     */
    val serviceDocumentation: String

    /**
     * OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array
     * of BCP47 (RFC5646) language tag values. Not all languages and scripts are necessarily supported for all
     * Claim values.
     */
    val claimsLocalesSupported: List<String>

    /**
     * OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 (RFC5646)
     * language tag values.
     */
    val uiLocalesSupported: List<String>

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the `claims` parameter, with `true`
     * indicating support. If omitted, the default value is `false`.
     */
    val claimsParameterSupported: Boolean
        get() = false

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the `request` parameter, with `true`
     * indicating support. If omitted, the default value is `false`.
     */
    val requestParameterSupported: Boolean
        get() = false

    /**
     * OPTIONAL. Boolean value specifying whether the OP supports use of the `request_uri` parameter, with `true`
     * indicating support. If omitted, the default value is `true`.
     */
    val requestUriParameterSupported: Boolean
        get() = true

    /**
     * OPTIONAL. Boolean value specifying whether the OP requires any `request_uri` values used to be pre-registered
     * using the `request_uris` registration parameter. Pre-registration is REQUIRED when the value is `true`.
     * If omitted, the default value is `false`.
     */
    val requireRequestUriRegistration: Boolean
        get() = false

    /**
     * OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's
     * requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD
     * display this URL to the person registering the Client if it is given.
     */
    val opPolicyUri: String

    fun validate() {
        check(issuer.isNotEmpty())

        // endpoints
        check(authorizationEndpoint.isNotEmpty())
        check(tokenEndpoint.isNotEmpty())
        check(userInfoEndpoint.isNotEmpty())
        check(jwksUri.isNotEmpty())
        check(registrationEndpoint.isNotEmpty())

        // scope
        check(scopesSupported.contains(StandardScope.openid))

        // response_type
        check(responseTypesSupported.flatMap { it.split(space) }.toSet().map {
            OidcResponseTypeValidator.validate(
                it
            )
        }.isNotEmpty())

        // response_mode
        check(responseModeSupported.map { ResponseModeValidator.validate(it) }.isNotEmpty())

        // grant_type
        check(grantTypesSupported.map { OAuthGrantTypeValidator.validate(it) }.containsAll(
            listOf(
                GrantType.authorizationCode,
                GrantType.implicit
            ))
        )

        // subject_type
        check(subjectTypesSupported.map { SubjectTypeValidator.validate(it) }.isNotEmpty())

        // id_token
        check(idTokenSigningAlgorithmValuesSupported.map { SigningAlgorithmValidator.validate(it) }.contains(
            JwtSigningAlgorithm.RS256.spec)
        )
        idTokenEncryptionAlgorithmValuesSupported.forEach { EncryptionAlgorithmValidator.validate(it) }
        idTokenEncryptionEncodingValuesSupported.forEach { EncryptionEncodingValidator.validate(it) }
        check(!(idTokenEncryptionAlgorithmValuesSupported.isNotEmpty() xor idTokenEncryptionEncodingValuesSupported.isNotEmpty()))

        // user info
        userInfoSigningAlgorithmValuesSupported.forEach { SigningAlgorithmValidator.validate(it) }
        userInfoEncryptionAlgorithmValuesSupported.forEach { EncryptionAlgorithmValidator.validate(it) }
        userInfoEncryptionEncodingValuesSupported.forEach { EncryptionEncodingValidator.validate(it) }
        check(!(userInfoEncryptionAlgorithmValuesSupported.isNotEmpty() xor userInfoEncryptionEncodingValuesSupported.isNotEmpty()))

        // request object
        check(requestObjectSigningAlgorithmValuesSupported.map {
            SigningAlgorithmValidator.validate(
                it
            )
        }.containsAll(
            listOf(JwtSigningAlgorithm.RS256.spec, JwtSigningAlgorithm.None.spec))
        )
        requestObjectEncryptionAlgorithmValuesSupported.forEach {
            EncryptionAlgorithmValidator.validate(
                it
            )
        }
        requestObjectEncryptionEncodingValuesSupported.forEach {
            EncryptionEncodingValidator.validate(
                it
            )
        }
        check(!(requestObjectEncryptionAlgorithmValuesSupported.isNotEmpty() xor requestObjectEncryptionEncodingValuesSupported.isNotEmpty()))

        // token endpoint auth
        check(tokenEndpointAuthenticationMethodsSupported.map {
            OidcClientAuthenticationMethodValidator.validate(
                it
            )
        }.isNotEmpty())
        tokenEndpointAuthenticationSigningAlgorithmValuesSupported.forEach {
            SigningAlgorithmValidator.validate(
                it
            )
        }

        // misc
        displayValuesSupported.forEach { DisplayValidator.validate(it) }
        check(claimValuesSupported.map { ClaimTypeValidator.validate(it) }.isNotEmpty())
    }
}