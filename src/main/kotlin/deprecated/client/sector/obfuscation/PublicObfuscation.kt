package deprecated.client.sector.obfuscation

import deprecated.client.OidcClient
import deprecated.client.metadata.SubjectType

/**
 * Obfuscation provider capable of handling [SubjectType.Public]. When [OidcClient.subjectType] is [SubjectType.Unspecified],
 * it defaults to this provider.
 */
object PublicObfuscation : SubjectIdentifierObfuscation {

    override fun obfuscate(subjectId: String, client: OidcClient): String {
        check(
            when (client.subjectType) {
                SubjectType.Public,
                SubjectType.Unspecified -> true
                else -> false
            }
        ) {
            "${javaClass.name} can only handle clients where subject_type=public"
        }
        return subjectId
    }
}