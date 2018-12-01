package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthException

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
        { OAuthException(status, code, "Server requires user interaction to proceed, but prompt <none> was specified.") }
}

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
        { OAuthException(status, code, "Server needs to display authentication UI to end user, but prompt <none> was specified.") }

    val reEntryInVain : () -> Throwable =
        { OAuthException(status, code, "Server cannot establish authentication after an active login attempt.") }

    val error : (String) -> Throwable =
        { reason -> OAuthException(status, code, reason) }
}

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
        { OAuthException(status, code, "Server needs to prompt the user to select among multiple active sessions, but prompt <none> was specified.") }
}

// consent_required
// ----------------
// The Authorization Server requires End-User consent. This error
// MAY be returned when the prompt parameter value in the Authentication
// Request is none, but the Authentication Request cannot be completed
// without displaying a user interface for End-User consent.
object ConsentRequired {
    private const val code = "consent_required"
    private const val status = 400

    val nonePrompt: () -> Throwable =
        { OAuthException(status, code, "Server needs to prompt user for consent, but prompt <none> was specified.") }
}

// invalid_request_uri
// -------------------
// The request_uri in the Authorization Request returns an error or
// contains invalid data.
object InvalidRequestUri {
    private const val code = "invalid_request_uri"
    private const val status = 400

    val none200: (Int) -> Throwable =
        { i -> OAuthException(status, code, "Request URI returned invalid response status ($i).") }

    val invalid: () -> Throwable =
        { OAuthException(status, code, "Request URI returned invalid data.") }

    val badHash: () -> Throwable =
        { OAuthException(status, code, "Request URI data does not match its hash.") }

    val rouge: () -> Throwable =
        { OAuthException(status, code, "Request URI was not pre-registered with client.") }

    val tooLong: () -> Throwable =
        { OAuthException(status, code, "Request URI must not exceed 512 ASCII characters.") }
}

// invalid_request_object
// ----------------------
// The request parameter contains an invalid Request Object.
object InvalidRequestObject {
    private const val code = "invalid_request_object"
    private const val status = 400

    val invalid: () -> Throwable =
        { OAuthException(status, code, "Request object contained invalid data.") }
}

// request_not_supported
// ---------------------
// The OP does not support use of the request parameter defined in
// Section 6 (https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests).
object RequestNotSupported {
    private const val code = "request_not_supported"
    private const val status = 400

    val unsupported: (String) -> Throwable =
        { param -> OAuthException(status, code, "The value or use of request parameter <$param> is not supported.") }
}

// request_uri_not_supported
// -------------------------
// The OP does not support use of the request_uri parameter defined in
// Section 6 (https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests).
object RequestUriNotSupported {
    private const val code = "request_uri_not_supported"
    private const val status = 400

    val unsupported: () -> Throwable =
        { OAuthException(status, code, "The use of request_uri parameter is not supported.") }
}

// registration_not_supported
// --------------------------
// The OP does not support use of the registration parameter defined in Section
// 7.2.1 (https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter).
object RegistrationNotSupported {
    private const val code = "registration_not_supported"
    private const val status = 400

    val unsupported: () -> Throwable =
        { OAuthException(status, code, "The use of registration parameter is not supported.") }
}