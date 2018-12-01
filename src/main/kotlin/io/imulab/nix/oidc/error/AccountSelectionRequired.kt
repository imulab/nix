package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// account_selection_required
// --------------------------
// The End-User is REQUIRED to select a session at the Authorization
// Server. The End-User MAY be authenticated at the Authorization
// Server with different associated accounts, but the End-User did
// not select a session. This error MAY be returned when the prompt
// parameter value in the Authentication Request is none, but the
// Authentication Request cannot be completed without displaying a
// user interface to prompt for a session to use.
object AccountSelectionRequired {
    private const val code = "account_selection_required"
    private const val status = 400

    val nonePrompt: () -> Throwable =
        {
            OAuthException(
                status,
                code,
                "Server needs to prompt the user to select among multiple active sessions, but prompt <none> was specified."
            )
        }
}