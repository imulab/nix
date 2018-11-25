package deprecated.client.sector.obfuscation

import deprecated.client.OidcClient
import deprecated.client.metadata.SubjectType

class DefaultObfuscation(private val public: PublicObfuscation,
                         private val pairwise: PairwiseObfuscation
): SubjectIdentifierObfuscation {

    override fun obfuscate(subjectId: String, client: OidcClient): String {
        return when (client.subjectType) {
            SubjectType.Public, SubjectType.Unspecified -> PublicObfuscation.obfuscate(
                subjectId,
                client
            )
            SubjectType.Pairwise -> pairwise.obfuscate(subjectId, client)
        }
    }
}