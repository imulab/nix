package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// login_required
// --------------
// The Authorization Server requires End-User authentication.
// This error MAY be returned when the prompt parameter value in
// the Authentication Request is none, but the Authentication
// Request cannot be completed without displaying a user interface
// for End-User authentication.
object LoginRequired {
    const val code = "login_required"
    private const val status = 400

    val nonePrompt: () -> Throwable =
        {
            OAuthException(
                status,
                code,
                "Server needs to display authentication UI to end user, but prompt <none> was specified."
            )
        }

    val reEntryInVain : () -> Throwable =
        {
            OAuthException(
                status,
                code,
                "Server cannot establish authentication after an active login attempt."
            )
        }

    val error : (String) -> Throwable =
        { reason -> OAuthException(status, code, reason) }
}