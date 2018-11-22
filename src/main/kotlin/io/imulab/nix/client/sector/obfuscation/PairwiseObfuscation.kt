package io.imulab.nix.client.sector.obfuscation

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.metadata.SubjectType
import io.imulab.nix.crypt.hash.HashAlgorithmProvider
import io.imulab.nix.crypt.hash.ShaHashAlgorithmProvider
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import java.nio.charset.StandardCharsets

class PairwiseObfuscation(
    private val salt: ByteArray,
    private val algorithm: HashAlgorithmProvider = ShaHashAlgorithmProvider.sha256()
) : SubjectIdentifierObfuscation {

    override fun obfuscate(subjectId: String, client: OidcClient): String {
        check(client.subjectType == SubjectType.Pairwise) {
            "${javaClass.name} can only handle clients where subject_type=pairwise"
        }

        return (getEffectiveSectorIdentifier(client).toByteArray(StandardCharsets.UTF_8) +
                subjectId.toByteArray(StandardCharsets.UTF_8) +
                salt).let {
            algorithm.hash(it).toString(StandardCharsets.UTF_8)
        }
    }

    private fun getEffectiveSectorIdentifier(client: OidcClient): String {
        if (client.sectorIdentifierUri.isNotBlank())
            return Url(client.sectorIdentifierUri).also { check(it.protocol == URLProtocol.HTTPS) }.host

        with(client.redirectUris.map { Url(it).host }.toSet()) {
            if (size == 0 || size > 1)
                TODO("client sector identifier uri cannot be determined")
            else
                return this.first()
        }
    }
}