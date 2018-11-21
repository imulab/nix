package io.imulab.nix.client.sector.obfuscation

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.metadata.SubjectType

class DefaultObfuscation(private val public: PublicObfuscation,
                         private val pairwise: PairwiseObfuscation): SubjectIdentifierObfuscation {

    override fun obfuscate(subjectId: String, client: OidcClient): String {
        return when (client.subjectType) {
            SubjectType.Public, SubjectType.Unspecified -> public.obfuscate(subjectId, client)
            SubjectType.Pairwise -> pairwise.obfuscate(subjectId, client)
        }
    }
}