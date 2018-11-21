package io.imulab.nix.client

import io.imulab.nix.client.metadata.ApplicationType
import io.imulab.nix.client.metadata.AuthenticationMethod
import io.imulab.nix.client.metadata.SubjectType
import io.imulab.nix.crypt.alg.EncryptionAlgorithm
import io.imulab.nix.crypt.alg.KeyManagementAlgorithm
import io.imulab.nix.crypt.alg.SigningAlgorithm

interface OidcClient: OAuthClient {

    /**
     * OPTIONAL. Kind of the application.
     * @see ApplicationType
     */
    val applicationType: ApplicationType

    /**
     * OPTIONAL. Array of e-mail addresses of people responsible for this Client.
     * This might be used by some providers to enable a Web user interface to modify the Client information.
     */
    val contacts: Set<String>

    /**
     * OPTIONAL. URL that references a logo for the Client application.
     * If present, the server SHOULD display this image to the End-User during approval. The value of this field
     * MUST point to a valid image file.
     */
    val logoUri: String

    /**
     * OPTIONAL. URL of the home page of the Client.
     * The value of this field MUST point to a valid Web page. If present, the server SHOULD display this URL to
     * the End-User in a followable fashion.
     */
    val clientUri: String

    /**
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the how the profile data will be used.
     * The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this URL to the
     * End-User if it is given.
     */
    val policyUri: String

    /**
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the Relying Party's terms of service.
     * The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this URL to the End-User if it is given.
     */
    val termsOfServiceUri: String

    /**
     * OPTIONAL. URL for the Client's JSON Web Key Set document.
     * If the Client signs requests to the Server, it contains the signing key(s) the Server uses to validate signatures
     * from the Client. The JWK Set MAY also contain the Client's encryption keys(s), which are used by the Server to
     * encrypt responses to the Client. When both signing and encryption keys are made available, a use (Key Use)
     * parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
     * Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED,
     * as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided.
     * When used, the bare key values MUST still be present and MUST match those in the certificate.
     */
    val jsonWebKeySetUri: String

    /**
     * OPTIONAL. Client's JSON Web Key Set document, passed by (JSON) value.
     * The semantics of the jwks parameter are the same as the jwks_uri parameter, other than that the JWK Set is
     * passed by value, rather than by reference. This parameter is intended only to be used by Clients that,
     * for some reason, are unable to use the jwks_uri parameter, for instance, by native applications that might not
     * have a location to host the contents of the JWK Set. If a Client can use jwks_uri, it MUST NOT use jwks.
     * One significant downside of jwks is that it does not enable key rotation (which jwks_uri does). The jwks_uri
     * and jwks parameters MUST NOT be used together.
     */
    val jsonWebKeySetValue: String

    /**
     * OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP.
     * The URL references a file with a single JSON array of redirect_uri values. Providers that use pairwise
     * sub (subject) values SHOULD utilize the sector_identifier_uri value provided in the Subject Identifier
     * calculation for pairwise identifiers.
     */
    val sectorIdentifierUri: String

    /**
     * OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported Discovery parameter
     * contains a list of the supported subject_type values for this server. Valid types include pairwise and public.
     *
     * @see SubjectType
     */
    val subjectType: SubjectType

    /**
     * OPTIONAL. JWS alg algorithm REQUIRED for signing the ID Token issued to this Client.
     * The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return
     * no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow).
     * The default, if omitted, is RS256. The public key for validating the signature is provided by retrieving the
     * JWK Set referenced by the jwks_uri element.
     */
    val idTokenSignedResponseAlgorithm: SigningAlgorithm

    /**
     * OPTIONAL. JWE alg algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If this is requested, the response will be signed then encrypted, with the result being a Nested JWT.
     * The default, if omitted, is that no encryption is performed.
     */
    val idTokenEncryptedResponseAlgorithm: KeyManagementAlgorithm?

    /**
     * OPTIONAL. JWE enc algorithm REQUIRED for encrypting the ID Token issued to this Client.
     * If id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
     * When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
     */
    val idTokenEncryptedResponseEncoding: EncryptionAlgorithm?

    /**
     * OPTIONAL. JWS alg algorithm REQUIRED for signing UserInfo Responses. If this is specified, the response will be
     * JWT serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the Claims
     * as a UTF-8 encoded JSON object using the application/json content-type.
     */
    val userInfoSignedResponseAlgorithm: SigningAlgorithm?

    /**
     * OPTIONAL. JWE alg algorithm REQUIRED for encrypting UserInfo Responses.
     * If both signing and encryption are requested, the response will be signed then encrypted, with the result being
     * a Nested JWT. The default, if omitted, is that no encryption is performed.
     */
    val userInfoEncryptedResponseAlgorithm: KeyManagementAlgorithm?

    /**
     * OPTIONAL. JWE enc algorithm REQUIRED for encrypting UserInfo Responses.
     * If userinfo_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
     * When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
     */
    val userInfoEncryptedResponseEncoding: EncryptionAlgorithm?

    /**
     * OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP.
     * Servers MAY repository the contents of the files referenced by these URIs and not retrieve them at the time they are
     * used in a request. OPs can require that request_uri values used be pre-registered with the
     * require_request_uri_registration discovery parameter. If the contents of the request file could ever change,
     * these URI values SHOULD include the base64url encoded SHA-256 hash value of the file contents referenced
     * by the URI as the value of the URI fragment. If the fragment value used for a URI changes, that signals the
     * server that its cached value for that URI with the old fragment value is no longer valid.
     */
    val requestUris: List<String>

    /**
     * OPTIONAL. JWS alg algorithm that MUST be used for signing Request Objects sent to the OP.
     * All Request Objects from this Client MUST be rejected, if not signed with this algorithm. This algorithm MUST be
     * used both when the Request Object is passed by value (using the request parameter) and when it is passed by
     * reference (using the request_uri parameter). Servers SHOULD support RS256. The value none MAY be used.
     * The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
     */
    val requestObjectSigningAlgorithm: SigningAlgorithm

    /**
     * OPTIONAL. JWE alg algorithm the RP is declaring that it may use for encrypting Request Objects sent to the OP.
     * This parameter SHOULD be included when symmetric encryption will be used, since this signals to the OP that a
     * client_secret value needs to be returned from which the symmetric key will be derived, that might not
     * otherwise be returned. The RP MAY still use other supported encryption algorithms or send unencrypted
     * Request Objects, even when this parameter is present. If both signing and encryption are requested, the
     * Request Object will be signed then encrypted, with the result being a Nested JWT. The default, if omitted,
     * is that the RP is not declaring whether it might encrypt any Request Objects.
     */
    val requestObjectEncryptionAlgorithm: KeyManagementAlgorithm?

    /**
     * OPTIONAL. JWE enc algorithm the RP is declaring that it may use for encrypting Request Objects sent to the OP.
     * If request_object_encryption_alg is specified, the default for this value is A128CBC-HS256.
     * When request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
     */
    val requestObjectEncryptionEncoding: EncryptionAlgorithm?

    /**
     * OPTIONAL. Requested Client Authentication method for the Token Endpoint.
     * The options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none.
     * Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic.
     *
     * @see AuthenticationMethod
     */
    val tokenEndpointAuthenticationMethod: AuthenticationMethod

    /**
     * OPTIONAL. JWS alg algorithm that MUST be used for signing the JWT used to authenticate the Client at the Token
     * Endpoint for the private_key_jwt and client_secret_jwt authentication methods. All Token Requests using these
     * authentication methods from this Client MUST be rejected, if the JWT is not signed with this algorithm.
     * Servers SHOULD support RS256. The value none MUST NOT be used. The default, if omitted, is that any algorithm
     * supported by the OP and the RP MAY be used.
     */
    val tokenEndpointAuthenticationSigningAlgorithm: SigningAlgorithm

    /**
     * OPTIONAL. Default Maximum Authentication Age.
     * Specifies that the End-User MUST be actively authenticated if the End-User was authenticated longer ago than the
     * specified number of seconds. The max_age request parameter overrides this default value.
     * If omitted, no default Maximum Authentication Age is specified.
     */
    val defaultMaxAgeSeconds: Long

    /**
     * OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED.
     * It is REQUIRED when the value is true. (If this is false, the auth_time Claim can still be dynamically requested
     * as an individual Claim for the ID Token using the claims request parameter described in Section 5.5.1 of OpenID Connect Core 1.0.)
     * If omitted, the default value is false.
     */
    val requireAuthenticationTime: Boolean

    /**
     * OPTIONAL. Default requested Authentication Context Class Reference values.
     * Array of strings that specifies the default acr values that the OP is being requested to use for processing
     * requests from this Client, with the values appearing in order of preference. The Authentication Context Class
     * satisfied by the authentication performed is returned as the acr Claim Value in the issued ID Token.
     * The acr Claim is requested as a Voluntary Claim by this parameter. The acr_values_supported discovery element
     * contains a list of the supported acr values supported by this server. Values specified in the acr_values
     * request parameter or an individual acr Claim request override these default values.
     */
    val defaultAcrValues: List<String>

    /**
     * OPTIONAL. URI using the https scheme that a third party can use to initiate a login by the RP,O
     * as specified in Section 4 of OpenID Connect Core 1.0. The URI MUST accept requests via both GET and POST.
     * The Client MUST understand the login_hint and iss parameters and SHOULD support the target_link_uri parameter.
     */
    val initiateLoginUri: String
}