package deprecated.client.sector.obfuscation

import deprecated.client.OidcClient

/**
 * This interface provides function to obfuscate a subject's identifier for a particular client. This is mainly to
 * ensure that clients (optionally) see different subject ids so they cannot not correlate information on the subject
 * using different client accounts without explicit permission.
 */
interface SubjectIdentifierObfuscation {

    /**
     * Perform obfuscation for the given [subjectId] for [client].
     *
     * @return Obfuscated subject id.
     */
    fun obfuscate(subjectId: String, client: OidcClient): String
}