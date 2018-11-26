package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthContext
import org.jose4j.jwk.JsonWebKeySet
import java.time.Duration

/**
 * Global server configuration data.
 *
 * TODO consult open id connect discovery 1.0 spec. some of its features are not needed at the moment, hence not included.
 */
interface OidcContext : OAuthContext {

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
     * URL where clients can download the publicly available server json web key set.
     */
    val masterJsonWebKeySetUrl: String
}