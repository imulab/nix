package deprecated.client.metadata

import deprecated.support.OAuthEnum

enum class ApplicationType(override val specValue: String): OAuthEnum {
    /**
     * Default for ApplicationType.
     * Web Clients using the OAuth Implicit Grant Type MUST only register URLs
     * using the https scheme as redirect_uris; they MUST NOT use localhost
     * as the hostname.
     */
    Web("web"),

    /**
     * Native Clients MUST only register redirect_uris using custom URI schemes
     * or URLs using the http: scheme with localhost as the hostname.
     */
    Native("native")
}