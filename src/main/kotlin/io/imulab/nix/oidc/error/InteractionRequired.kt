package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// interaction_required
// --------------------
// The Authorization Server requires End-User interaction of
// some form to proceed. This error MAY be returned when the
// prompt parameter value in the Authentication Request is
// none, but the Authentication Request cannot be completed
// without displaying a user interface for End-User interaction.
object InteractionRequired {
    private const val code = "interaction_required"
    private const val status = 400

    val nonePrompt: () -> Throwable =
        {
            OAuthException(
                status,
                code,
                "Server requires user interaction to proceed, but prompt <none> was specified."
            )
        }
}