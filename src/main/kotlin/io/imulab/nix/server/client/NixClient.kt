package io.imulab.nix.server.client

import io.imulab.nix.oauth.reserved.AuthenticationMethod
import io.imulab.nix.oauth.reserved.ClientType
import io.imulab.nix.oauth.ClientTypeValidator
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.client.OidcClient
import java.util.*
import kotlin.collections.LinkedHashSet

class NixClient(
    override val id: String = UUID.randomUUID().toString(),
    override val secret: ByteArray = ByteArray(0),
    override val name: String,
    override val type: String,
    override val redirectUris: Set<String>,
    override val responseTypes: Set<String>,
    override val grantTypes: Set<String>,
    override val scopes: Set<String>,
    override val applicationType: String,
    override val contacts: LinkedHashSet<String>,
    override val logoUri: String,
    override val clientUri: String,
    override val policyUri: String,
    override val tosUri: String,
    override val jwksUri: String,
    override val jwks: String,
    override val sectorIdentifierUri: String,
    override val subjectType: String,
    override val idTokenSignedResponseAlgorithm: JwtSigningAlgorithm,
    override val idTokenEncryptedResponseAlgorithm: JweKeyManagementAlgorithm,
    override val idTokenEncryptedResponseEncoding: JweContentEncodingAlgorithm,
    override val requestObjectSigningAlgorithm: JwtSigningAlgorithm,
    override val requestObjectEncryptionAlgorithm: JweKeyManagementAlgorithm,
    override val requestObjectEncryptionEncoding: JweContentEncodingAlgorithm,
    override val userInfoSignedResponseAlgorithm: JwtSigningAlgorithm,
    override val userInfoEncryptedResponseAlgorithm: JweKeyManagementAlgorithm,
    override val userInfoEncryptedResponseEncoding: JweContentEncodingAlgorithm,
    override val tokenEndpointAuthenticationMethod: String,
    override val defaultMaxAge: Long,
    override val requireAuthTime: Boolean,
    override val defaultAcrValues: List<String>,
    override val initiateLoginUri: String,
    override val requestUris: List<String>
) : OidcClient {

    init {
        checkClientTypeVsSecret()
        checkEncryptionAlgorithmRelation()
        checkResponseTypeVsIdTokenSigningAlgorithm()
    }

    private fun checkClientTypeVsSecret() {
        when (type) {
            ClientType.confidential -> check(secret.isNotEmpty()) { "confidential client should have non-empty secret." }
            ClientType.public -> check(secret.isEmpty()) { "public client should have empty secret." }
        }
    }

    private fun checkEncryptionAlgorithmRelation() {
        if (requestObjectEncryptionAlgorithm != JweKeyManagementAlgorithm.None)
            check(requestObjectEncryptionEncoding != JweContentEncodingAlgorithm.None) {
                "request_object_encryption_alg and request_object_encryption_enc must both be set."
            }
        if (userInfoEncryptedResponseAlgorithm != JweKeyManagementAlgorithm.None)
            check(userInfoEncryptedResponseEncoding != JweContentEncodingAlgorithm.None) {
                "userinfo_encrypted_response_alg and userinfo_encrypted_response_enc must both be set."
            }
        if (idTokenEncryptedResponseAlgorithm != JweKeyManagementAlgorithm.None)
            check(idTokenEncryptedResponseEncoding != JweContentEncodingAlgorithm.None) {
                "id_token_encrypted_response_alg and id_token_encrypted_response_enc must both be set."
            }
    }

    private fun checkResponseTypeVsIdTokenSigningAlgorithm() {
        if (idTokenSignedResponseAlgorithm == JwtSigningAlgorithm.None)
            check(!responseTypes.contains(ResponseType.code)) {
                """
                    Client selected response_type=code which is bound to use token endpoint for token issuance.
                    However, if client needs to use token endpoint, id_token_signed_response_alg cannot be none.
                """.trimIndent()
            }
    }

    class Builder(
        var id: String = UUID.randomUUID().toString().toLowerCase(),
        var secret: ByteArray = ByteArray(0),
        var name: String = "",
        var type: String = ClientType.confidential,
        var redirectUris: MutableSet<String> = mutableSetOf(),
        var responseTypes: MutableSet<String> = mutableSetOf(),
        var grantTypes: MutableSet<String> = mutableSetOf(),
        var scopes: MutableSet<String> = mutableSetOf(),
        var applicationType: String = ApplicationType.web,
        var contacts: LinkedHashSet<String> = LinkedHashSet(),
        var logoUri: String = "",
        var clientUri: String = "",
        var policyUri: String = "",
        var tosUri: String = "",
        var jwksUri: String = "",
        var jwks: String = "",
        var sectorIdentifierUri: String = "",
        var subjectType: String = SubjectType.public,
        var idTokenSignedResponseAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
        var idTokenEncryptedResponseAlgorithm: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm.None,
        var idTokenEncryptedResponseEncoding: JweContentEncodingAlgorithm = JweContentEncodingAlgorithm.None,
        var requestObjectSigningAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
        var requestObjectEncryptionAlgorithm: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm.None,
        var requestObjectEncryptionEncoding: JweContentEncodingAlgorithm = JweContentEncodingAlgorithm.None,
        var userInfoSignedResponseAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.None,
        var userInfoEncryptedResponseAlgorithm: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm.None,
        var userInfoEncryptedResponseEncoding: JweContentEncodingAlgorithm = JweContentEncodingAlgorithm.None,
        var tokenEndpointAuthenticationMethod: String = AuthenticationMethod.clientSecretPost,
        var defaultMaxAge: Long = 0,
        var requireAuthTime: Boolean = false,
        var defaultAcrValues: MutableList<String> = mutableListOf(),
        var initiateLoginUri: String = "",
        var requestUris: MutableList<String> = mutableListOf()
    ) {

        private fun validate() {
            ClientTypeValidator.validate(type)
            // TODO more
        }

        fun build(): NixClient {
            validate()
            return NixClient(
                id = id,
                secret = secret,
                name = name,
                type = type,
                redirectUris = redirectUris,
                responseTypes = responseTypes,
                grantTypes = grantTypes,
                scopes = scopes,
                applicationType = applicationType,
                contacts = contacts,
                logoUri = logoUri,
                clientUri = clientUri,
                policyUri = policyUri,
                tosUri = tosUri,
                jwksUri = jwksUri,
                jwks = jwks,
                sectorIdentifierUri = sectorIdentifierUri,
                subjectType = subjectType,
                idTokenSignedResponseAlgorithm = idTokenSignedResponseAlgorithm,
                idTokenEncryptedResponseAlgorithm = idTokenEncryptedResponseAlgorithm,
                idTokenEncryptedResponseEncoding = idTokenEncryptedResponseEncoding,
                requestObjectSigningAlgorithm = requestObjectSigningAlgorithm,
                requestObjectEncryptionAlgorithm = requestObjectEncryptionAlgorithm,
                requestObjectEncryptionEncoding = requestObjectEncryptionEncoding,
                userInfoSignedResponseAlgorithm = userInfoSignedResponseAlgorithm,
                userInfoEncryptedResponseAlgorithm = userInfoEncryptedResponseAlgorithm,
                userInfoEncryptedResponseEncoding = userInfoEncryptedResponseEncoding,
                tokenEndpointAuthenticationMethod = tokenEndpointAuthenticationMethod,
                defaultMaxAge = defaultMaxAge,
                requireAuthTime = requireAuthTime,
                defaultAcrValues = defaultAcrValues,
                initiateLoginUri = initiateLoginUri,
                requestUris = requestUris
            )
        }
    }
}