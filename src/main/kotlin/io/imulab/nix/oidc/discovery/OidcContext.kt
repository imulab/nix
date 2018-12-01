package io.imulab.nix.oidc.discovery

import io.imulab.nix.oauth.*
import org.jose4j.jwk.JsonWebKeySet
import java.time.Duration

/**
 * Global server configuration data.
 */
interface OidcContext : OAuthContext, Discovery {

    /**
     * Time to live for access token. Suggested value is 1 day.
     */
    val idTokenLifespan: Duration

    /**
     * Json web key set used by the server to perform signature/verification
     * and encryption/decryption related tasks. Keys placed inside must have
     * key use and key id set.
     */
    val masterJsonWebKeySet: JsonWebKeySet

    /**
     * Minimum length for the `nonce` parameter.
     */
    val nonceEntropy: Int

    override fun validate() {
        super<OAuthContext>.validate()
        super<Discovery>.validate()

        check(!idTokenLifespan.isZero) { "idTokenLifespan must not be zero." }

        check(nonceEntropy >= 0) { "nonce entropy must not be negative." }
    }
}