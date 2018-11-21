package io.imulab.nix.client

import com.google.gson.annotations.SerializedName
import io.imulab.nix.client.metadata.*
import io.imulab.nix.crypt.alg.EncryptionAlgorithm
import io.imulab.nix.crypt.alg.KeyManagementAlgorithm
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.support.JsonSkip
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Default implementation of [OAuthClient] and [OidcClient] that will be used in this application.
 */
data class Client(

    @SerializedName("client_id")
    override val id: String = UUID.randomUUID().toString(),

    @SerializedName("client_name")
    override val name: String = "",

    @JsonSkip
    val hashedSecret: String = "",

    @SerializedName("client_type")
    override val type: ClientType = ClientType.CONFIDENTIAL,

    @SerializedName("redirect_uris")
    override val redirectUris: List<String> = emptyList(),

    @SerializedName("response_types")
    override val responseTypes: Set<ResponseType> = setOf(ResponseType.Code),

    @SerializedName("grant_types")
    override val grantTypes: Set<GrantType> = setOf(GrantType.AuthorizationCode),

    override val scopes: Set<String> = emptySet(),

    @SerializedName("application_type")
    override val applicationType: ApplicationType = ApplicationType.Web,

    @SerializedName("contacts")
    override val contacts: Set<String> = emptySet(),

    @SerializedName("logo_uri")
    override val logoUri: String = "",

    @SerializedName("client_uri")
    override val clientUri: String = "",

    @SerializedName("policy_uri")
    override val policyUri: String = "",

    @SerializedName("tos_uri")
    override val termsOfServiceUri: String = "",

    @SerializedName("jwks_uri")
    override val jsonWebKeySetUri: String = "",

    @SerializedName("jwks")
    override val jsonWebKeySetValue: String = "",

    @SerializedName("sector_identifier_uri")
    override val sectorIdentifierUri: String = "",

    @SerializedName("subject_type")
    override val subjectType: SubjectType = SubjectType.Public,

    @SerializedName("id_token_signed_response_alg")
    override val idTokenSignedResponseAlgorithm: SigningAlgorithm = SigningAlgorithm.RS256,

    @SerializedName("id_token_encrypted_response_alg")
    override val idTokenEncryptedResponseAlgorithm: KeyManagementAlgorithm? = null,

    @SerializedName("id_token_encrypted_response_enc")
    override val idTokenEncryptedResponseEncoding: EncryptionAlgorithm? = null,

    @SerializedName("userinfo_signed_response_alg")
    override val userInfoSignedResponseAlgorithm: SigningAlgorithm? = null,

    @SerializedName("userinfo_encrypted_response_alg")
    override val userInfoEncryptedResponseAlgorithm: KeyManagementAlgorithm? = null,

    @SerializedName("userinfo_encrypted_response_enc")
    override val userInfoEncryptedResponseEncoding: EncryptionAlgorithm? = null,

    @SerializedName("request_uris")
    override val requestUris: List<String> = emptyList(),

    @SerializedName("request_object_signing_alg")
    override val requestObjectSigningAlgorithm: SigningAlgorithm = SigningAlgorithm.RS256,

    @SerializedName("request_object_encryption_alg")
    override val requestObjectEncryptionAlgorithm: KeyManagementAlgorithm? = null,

    @SerializedName("request_object_encryption_enc")
    override val requestObjectEncryptionEncoding: EncryptionAlgorithm? = null,

    @SerializedName("token_endpoint_auth_method")
    override val tokenEndpointAuthenticationMethod: AuthenticationMethod = AuthenticationMethod.Unspecified,

    @SerializedName("token_endpoint_auth_signing_alg")
    override val tokenEndpointAuthenticationSigningAlgorithm: SigningAlgorithm = SigningAlgorithm.RS256,

    @SerializedName("default_max_age")
    override val defaultMaxAgeSeconds: Long = Long.MAX_VALUE,

    @SerializedName("require_auth_time")
    override val requireAuthenticationTime: Boolean = false,

    @SerializedName("default_acr_values")
    override val defaultAcrValues: List<String> = emptyList(),

    @SerializedName("initiate_login_uri")
    override val initiateLoginUri: String = ""
) : OidcClient {
    override val secret: ByteArray
        get() = hashedSecret.toByteArray(StandardCharsets.UTF_8)
}