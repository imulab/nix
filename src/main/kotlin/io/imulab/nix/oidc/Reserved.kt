package io.imulab.nix.oidc

import deprecated.crypt.alg.HashAlgorithm
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType.WHITELIST
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.jwk.EllipticCurveJsonWebKey
import org.jose4j.jwk.OctetSequenceJsonWebKey
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers

object OidcParam {
    const val responseMode = "response_mode"
    const val nonce = "nonce"
    const val display = "display"
    const val prompt = "prompt"
    const val maxAge = "max_age"
    const val uiLocales = "ui_locales"
    const val idTokenHint = "id_token_hint"
    const val loginHint = "login_hint"
    const val acrValues = "acr_values"
    const val claims = "claims"
    const val claimsLocales = "claims_locales"
    const val request = "request"
    const val requestUri = "request_uri"
    const val registration = "registration"
    const val iss = "iss"
    const val targetLinkUri = "target_link_uri"
}

object StandardClaim {
    const val accessTokenHash = "at_hash"
    const val codeHash = "c_hash"
    const val nonce = "nonce"
    const val sub = "sub"
    const val name = "name"
    const val givenName = "given_name"
    const val familyName = "family_name"
    const val middleName = "middle_name"
    const val nickname = "nickname"
    const val preferredUsername = "preferred_username"
    const val profile = "profile"
    const val picture = "picture"
    const val website = "website"
    const val email = "email"
    const val emailVerified = "email_verified"
    const val gender = "gender"
    const val birthdate = "birthdate"
    const val zoneinfo = "zoneinfo"
    const val locale = "locale"
    const val phoneNumber = "phone_number"
    const val phoneNumberVerified = "phone_number_verified"
    const val address = "address"
    const val updatedAt = "updated_at"

    object Address {
        const val formatted = "formatted"
        const val streetAddress = "street_address"
        const val locality = "locality"
        const val region = "region"
        const val postalCode = "postal_code"
        const val country = "country"
    }
}

/**
 * Authentication method applicable to client. This is an extension to
 * the values existing in [io.imulab.nix.oauth.AuthenticationMethod] and
 * represents the authentication method that wasn't mentioned in OAuth 2.0
 * specification but mentioned in Open ID Connect 1.0 specification.
 */
object AuthenticationMethod {
    const val clientSecretJwt = "client_secret_jwt"
    const val privateKeyJwt = "private_key_jwt"
    const val none = "none"
}

object ApplicationType {
    const val web = "web"
    const val native = "native"
}

object SubjectType {
    const val pairwise = "pairwise"
    const val public = "public"
}

typealias KmId = KeyManagementAlgorithmIdentifiers
typealias CeId = ContentEncryptionAlgorithmIdentifiers
typealias AId = AlgorithmIdentifiers

/**
 * Signature algorithm used to sign and verify signatures.
 */
enum class JwtSigningAlgorithm(val spec: String, val algorithmIdentifier: String) {
    HS256("HS256", AId.HMAC_SHA256),
    HS384("HS384", AId.HMAC_SHA384),
    HS512("HS512", AId.HMAC_SHA512),
    RS256("RS256", AId.RSA_USING_SHA256),
    RS384("RS384", AId.RSA_USING_SHA384),
    RS512("RS512", AId.RSA_USING_SHA512),
    ES256("ES256", AId.ECDSA_USING_P256_CURVE_AND_SHA256),
    ES384("ES384", AId.ECDSA_USING_P384_CURVE_AND_SHA384),
    ES512("ES512", AId.ECDSA_USING_P521_CURVE_AND_SHA512),
    PS256("PS256", AId.RSA_PSS_USING_SHA256),
    PS384("PS384", AId.RSA_PSS_USING_SHA384),
    PS512("PS512", AId.RSA_PSS_USING_SHA512),
    None("none", AId.NONE);

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(WHITELIST, algorithmIdentifier)
}

/**
 * Key management algorithm used for JWE encryption/decryption.
 * [None] is a special value to indicate this algorithm is not
 * specified. Fields adopting [None] should be treated as if
 * the value is null.
 */
enum class JweKeyManagementAlgorithm(
    val spec: String,
    val algorithmIdentifier: String,
    val isSymmetric: Boolean
) {

    RSA1_5("RSA1_5", KmId.RSA1_5, false),
    RSA_OAEP("RSA-OAEP", KmId.RSA_OAEP, false),
    RSA_OAEP_256("RSA-OAEP-256", KmId.RSA_OAEP_256, false),
    ECDH_ES("ECDH-ES", KmId.ECDH_ES, false),
    ECDH_ES_A128KW("ECDH-ES+A128KW", KmId.ECDH_ES_A128KW, false),
    ECDH_ES_A192KW("ECDH-ES+A192KW", KmId.ECDH_ES_A192KW, false),
    ECDH_ES_A256KW("ECDH-ES+A256KW", KmId.ECDH_ES_A256KW, false),
    A128KW("A128KW", KmId.A128KW, true),
    A192KW("A192KW", KmId.A192KW, true),
    A256KW("A256KW", KmId.A256KW, true),
    A128GCMKW("A128GCMKW", KmId.A128GCMKW, true),
    A192GCMKW("A192GCMKW", KmId.A192GCMKW, true),
    A256GCMKW("A256GCMKW", KmId.A256GCMKW, true),
    PBES2_HS256_A128KW("PBES2-HS256+A128KW", KmId.PBES2_HS256_A128KW, true),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW", KmId.PBES2_HS384_A192KW, true),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW", KmId.PBES2_HS512_A256KW, true),
    DIRECT("dir", KmId.DIRECT, false),
    None("none", "", false);

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(WHITELIST, algorithmIdentifier)
}

/**
 * Content encoding algorithm used for JWE encryption/decryption.
 * [None] is a special value to indicate this algorithm is not
 * specified. Fields adopting [None] should be treated as if the
 * value is null.
 */
enum class JweContentEncodingAlgorithm(val spec: String, val algorithmIdentifier: String) {
    A128CBC_HS256("A128CBC-HS256", CeId.AES_128_CBC_HMAC_SHA_256),
    A192CBC_HS384("A192CBC-HS384", CeId.AES_192_CBC_HMAC_SHA_384),
    A256CBC_HS512("A256CBC-HS512", CeId.AES_256_CBC_HMAC_SHA_512),
    A128GCM("A128GCM", CeId.AES_128_GCM),
    A192GCM("A192GCM", CeId.AES_192_GCM),
    A256GCM("A256GCM", CeId.AES_256_GCM),
    None("none", "");

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(WHITELIST, algorithmIdentifier)
}