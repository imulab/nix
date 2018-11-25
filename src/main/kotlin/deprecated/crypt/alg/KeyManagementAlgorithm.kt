package deprecated.crypt.alg

import deprecated.support.OAuthEnum
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers

enum class KeyManagementAlgorithm(override val specValue: String, val identifier: String):
    OAuthEnum {

    RSA1_5("RSA1_5", KeyManagementAlgorithmIdentifiers.RSA1_5),
    RSA_OAEP("RSA-OAEP", KeyManagementAlgorithmIdentifiers.RSA_OAEP),
    RSA_OAEP_256("RSA-OAEP-256", KeyManagementAlgorithmIdentifiers.RSA_OAEP_256),
    ECDH_ES("ECDH-ES", KeyManagementAlgorithmIdentifiers.ECDH_ES),
    ECDH_ES_A128KW("ECDH-ES+A128KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW),
    ECDH_ES_A192KW("ECDH-ES+A192KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW),
    ECDH_ES_A256KW("ECDH-ES+A256KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW),

    A128KW("A128KW", KeyManagementAlgorithmIdentifiers.A128KW),
    A192KW("A192KW", KeyManagementAlgorithmIdentifiers.A192KW),
    A256KW("A256KW", KeyManagementAlgorithmIdentifiers.A256KW),

    A128GCMKW("A128GCMKW", KeyManagementAlgorithmIdentifiers.A128GCMKW),
    A192GCMKW("A192GCMKW", KeyManagementAlgorithmIdentifiers.A192GCMKW),
    A256GCMKW("A256GCMKW", KeyManagementAlgorithmIdentifiers.A256GCMKW),

    PBES2_HS256_A128KW("PBES2-HS256+A128KW", KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW", KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW", KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW),

    DIRECT("dir", KeyManagementAlgorithmIdentifiers.DIRECT);

    fun asAlgorithmConstraint(): AlgorithmConstraints =
            AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, this.identifier)
}