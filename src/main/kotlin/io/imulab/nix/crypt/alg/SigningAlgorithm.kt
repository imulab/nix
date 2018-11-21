package io.imulab.nix.crypt.alg

import io.imulab.nix.support.OAuthEnum
import org.jose4j.jwk.EllipticCurveJsonWebKey
import org.jose4j.jwk.OctetSequenceJsonWebKey
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers

enum class SigningAlgorithm(
    override val specValue: String,
    private val fullName: String,
    val hashAlgorithm: HashAlgorithm?,
    val alg: String,
    val keyType: String?
) : OAuthEnum {

    HS256(
        specValue = "HS256",
        fullName = "HMAC using SHA-256",
        hashAlgorithm = HashAlgorithm.SHA256,
        alg = AlgorithmIdentifiers.HMAC_SHA256,
        keyType = OctetSequenceJsonWebKey.KEY_TYPE),
    HS384(
        specValue = "HS384",
        fullName = "HMAC using SHA-384",
        hashAlgorithm = HashAlgorithm.SHA384,
        alg = AlgorithmIdentifiers.HMAC_SHA384,
        keyType = OctetSequenceJsonWebKey.KEY_TYPE),
    HS512(
        specValue = "HS512",
        fullName = "HMAC using SHA-512",
        hashAlgorithm = HashAlgorithm.SHA512,
        alg = AlgorithmIdentifiers.HMAC_SHA512,
        keyType = OctetSequenceJsonWebKey.KEY_TYPE),
    RS256(
        specValue = "RS256",
        fullName = "RSASSA-PKCS1-v1_5 using SHA-256",
        hashAlgorithm = HashAlgorithm.SHA256,
        alg = AlgorithmIdentifiers.RSA_USING_SHA256,
        keyType = RsaJsonWebKey.KEY_TYPE),
    RS384(
        specValue = "RS384",
        fullName = "RSASSA-PKCS1-v1_5 using SHA-384",
        hashAlgorithm = HashAlgorithm.SHA384,
        alg = AlgorithmIdentifiers.RSA_USING_SHA384,
        keyType = RsaJsonWebKey.KEY_TYPE),
    RS512(
        specValue = "RS512",
        fullName = "RSASSA-PKCS1-v1_5 using SHA-512",
        hashAlgorithm = HashAlgorithm.SHA512,
        alg = AlgorithmIdentifiers.RSA_USING_SHA512,
        keyType = RsaJsonWebKey.KEY_TYPE),
    ES256(
        specValue = "ES256",
        fullName = "ECDSA using P-256 and SHA-256",
        hashAlgorithm = HashAlgorithm.SHA256,
        alg = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
        keyType = EllipticCurveJsonWebKey.KEY_TYPE),
    ES384(
        specValue = "ES384",
        fullName = "ECDSA using P-384 and SHA-384",
        hashAlgorithm = HashAlgorithm.SHA384,
        alg = AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
        keyType = EllipticCurveJsonWebKey.KEY_TYPE),
    ES512(
        specValue = "ES512",
        fullName = "ECDSA using P-521 and SHA-512",
        hashAlgorithm = HashAlgorithm.SHA512,
        alg = AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512,
        keyType = EllipticCurveJsonWebKey.KEY_TYPE),
    PS256(
        specValue = "PS256",
        fullName = "RSASSA-PSS using SHA-512 and MGF1 with SHA-256",
        hashAlgorithm = HashAlgorithm.SHA256,
        alg = AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
        keyType = RsaJsonWebKey.KEY_TYPE),
    PS384(
        specValue = "PS384",
        fullName = "RSASSA-PSS using SHA-512 and MGF1 with SHA-384",
        hashAlgorithm = HashAlgorithm.SHA384,
        alg = AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
        keyType = RsaJsonWebKey.KEY_TYPE),
    PS512(
        specValue = "PS512",
        fullName = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512",
        hashAlgorithm = HashAlgorithm.SHA512,
        alg = AlgorithmIdentifiers.RSA_PSS_USING_SHA512,
        keyType = RsaJsonWebKey.KEY_TYPE),
    None(
        specValue = "none",
        fullName = "None",
        hashAlgorithm = null,
        alg = AlgorithmIdentifiers.NONE,
        keyType = null)
}