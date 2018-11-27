package io.imulab.nix.oidc.client

import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oidc.JweContentEncodingAlgorithm
import io.imulab.nix.oidc.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.JwtSigningAlgorithm

interface OidcClient : OAuthClient {

    /**
     * Optional. Kind of the application. Default should be set to web.
     */
    val applicationType: String

    /**
     * Optional. Array of e-mails for people responsible for this client.
     */
    val contacts: LinkedHashSet<String>

    /**
     * Optional. URL that references the client logo. If present, will be
     * displayed to the end user during approval.
     */
    val logoUri: String

    /**
     * Optional. URL to the home page of the client. If present, will be
     * enabled for the end user to follow during approval.
     */
    val clientUri: String

    /**
     * Optional. URL the RP provides to inform the end user how their
     * profile data will be used. If present, will be displayed to the
     * end user during approval.
     */
    val policyUri: String

    /**
     * Optional. URL the RP provides to inform the end user about their
     * terms of service. If present, will be displayed to the end user
     * during approval.
     */
    val tosUri: String

    /**
     * Optional. URL for the client's JSON Web Key Set. If registered, the
     * server should download and cache it to avoid request time round
     * trip.
     */
    val jwksUri: String

    /**
     * Optional. Client's JSON Web Key Set by value.
     */
    val jwks: String

    /**
     * Optional. URL using https scheme whose host component will be utilized
     * during pairwise pseudonymous subject value calculation. The URL itself
     * should point to a file with single JSON array of redirect_uri values.
     */
    val sectorIdentifierUri: String

    /**
     * Optional. The subject type of this client. This value determines how
     * pseudonymous subject value is calculated.
     */
    val subjectType: String

    /**
     * Optional. The JWT 'alg' header value. 'none' MUST NOT be used unless client
     * does not use token endpoint (reflected by its registered [responseTypes]).
     * By default, this should be set to RS256. The public key for validating the
     * signature should be retrievable via [jwksUri] or [jwks].
     */
    val idTokenSignedResponseAlgorithm: JwtSigningAlgorithm

    /**
     * Optional. The JWE 'alg' header value. If value is [JweKeyManagementAlgorithm.None],
     * id_token will only be signed. Otherwise, it will be signed and then encrypted.
     */
    val idTokenEncryptedResponseAlgorithm: JweKeyManagementAlgorithm

    /**
     * Optional. The JWE 'enc' header value. This value should be specified when
     * [idTokenEncryptedResponseAlgorithm] is specified. This means: when
     * [idTokenEncryptedResponseAlgorithm] is not [JweKeyManagementAlgorithm.None],
     * this value cannot be [JweContentEncodingAlgorithm.None] either. By default,
     * this value is A128CBC-HS256
     */
    val idTokenEncryptedResponseEncoding: JweContentEncodingAlgorithm

    /**
     * Optional. The JWT 'alg' header value. If not signed with this algorithm,
     * all request object sent to OP must be rejected. By default, this value
     * is RS256. [JwtSigningAlgorithm.None] may be used, but not recommended
     * unless request object is also encrypted.
     */
    val requestObjectSigningAlgorithm: JwtSigningAlgorithm

    /**
     * Optional. The JWE 'alg' header value. If a symmetric algorithm is used,
     * the OP should use the client's secret as key. If [JweKeyManagementAlgorithm.None],
     * the OP will treat request objects as unencrypted.
     */
    val requestObjectEncryptionAlgorithm: JweKeyManagementAlgorithm

    /**
     * Optional. The JWE 'enc' header value. By default, this value is A128CBC-HS256.
     * If [requestObjectEncryptionAlgorithm] is not [JweKeyManagementAlgorithm.None],
     * this value cannot be [JweContentEncodingAlgorithm.None]. Otherwise, this field
     * is ignored since no encryption/decryption will be performed on request object.
     */
    val requestObjectEncryptionEncoding: JweContentEncodingAlgorithm

    /**
     * Optional. The JWT 'alg' header value. By default, if omitted, the OP returns user
     * info as an UTF-8 encoded JSON object with 'application/json' set as Content-Type
     * header.
     */
    val userInfoSignedResponseAlgorithm: JwtSigningAlgorithm

    /**
     * Optional. The JWE 'alg' header value. It the value is [JweKeyManagementAlgorithm.None],
     * no encryption/decryption will be performed by OP.
     */
    val userInfoEncryptedResponseAlgorithm: JweKeyManagementAlgorithm

    /**
     * Optional. The JWE 'enc' header value. If [userInfoEncryptedResponseAlgorithm] is
     * set to values other than [JweKeyManagementAlgorithm.None], this value cannot be
     * set to [JweContentEncodingAlgorithm.None]. By default, this value is A128CBC-HS256.
     */
    val userInfoEncryptedResponseEncoding: JweContentEncodingAlgorithm

    /**
     * Optional. The method employed at the token endpoint to authenticate the client. If
     * omitted, the default method used should be client_secret_basic.
     *
     * @see io.imulab.nix.oauth.AuthenticationMethod
     * @see io.imulab.nix.oidc.AuthenticationMethod
     */
    val tokenEndpointAuthenticationMethod: String

    /**
     * Optional. Specifies the end user must be actively authenticated if the end user is
     * authenticated longer ago than the number of seconds specified by this value. This
     * value can be override by the max_age parameter in the request. By default, the value
     * '0' means no default max age. In this case, if no max_age is specified by the request,
     * the OP does not consider expiration when dealing with authentication sessions.
     */
    val defaultMaxAge: Long

    /**
     * Optional. Boolean value indicating that auth_time claim is required. By default, the
     * value is false. However, even when false, auth_time can still be dynamically requested
     * by requests utilizing the claims field.
     */
    val requireAuthTime: Boolean

    /**
     * Optional. A list of default acr values that the OP is requested to use during the request.
     */
    val defaultAcrValues: List<String>

    /**
     * Optional. URL using https scheme that a third party will use to initiate a login by the RP.
     * If this value is provided, the OP should direct end-user to this address when login is
     * required. Otherwise, end-user will be directed to server's default login page. This url
     * must accept both GET and POST requests. The client must understand login_hint and iss
     * parameters and support target_link_uri parameter.
     */
    val initiateLoginUri: String

    /**
     * Optional. Array of request_uri values pre-registered by the client to be used at request.
     * Servers can cache the contents of these value before to avoid round trip at request time.
     * Uris can include a base64 encoded SHA-256 hash of file contents as fragment component to
     * serve as a version. Server should retire cached requests and fetch new ones when these
     * hash does not match.
     */
    val requestUris: List<String>

    /**
     * Returns true if this client requires encryption for request object
     */
    fun requireRequestObjectEncryption(): Boolean =
        requestObjectEncryptionAlgorithm != JweKeyManagementAlgorithm.None

    /**
     * Returns true if this client requires encryption for user info response
     */
    fun requireUserInfoEncrption(): Boolean =
        userInfoEncryptedResponseAlgorithm != JweKeyManagementAlgorithm.None

    /**
     * Returns true if this client requires encryption for id_token
     */
    fun requireIdTokenEncryption(): Boolean =
        idTokenEncryptedResponseAlgorithm != JweKeyManagementAlgorithm.None
}