package io.imulab.nix.oidc

object OidcParam {
    const val nonce = "nonce"
    const val display = "display"
    const val prompt = "prompt"
    const val maxAge = "max_age"
    const val uiLocales = "ui_locales"
    const val idTokenHint = "id_token_hint"
    const val loginHint = "login_hint"
    const val acrValues = "acr_values"
    const val claims = "claims"
    const val claimsLocales = "claims_locales"
    const val request = "request"
    const val requestUri = "request_uri"
    const val registration = "registration"
}

object StandardClaim {
    const val accessTokenHash = "at_hash"
    const val codeHash = "c_hash"
    const val nonce = "nonce"
    const val sub = "sub"
    const val name = "name"
    const val givenName = "given_name"
    const val familyName = "family_name"
    const val middleName = "middle_name"
    const val nickname = "nickname"
    const val preferredUsername = "preferred_username"
    const val profile = "profile"
    const val picture = "picture"
    const val website = "website"
    const val email = "email"
    const val emailVerified = "email_verified"
    const val gender = "gender"
    const val birthdate = "birthdate"
    const val zoneinfo = "zoneinfo"
    const val locale = "locale"
    const val phoneNumber = "phone_number"
    const val phoneNumberVerified = "phone_number_verified"
    const val address = "address"
    const val updatedAt = "updated_at"

    object Address {
        const val formatted = "formatted"
        const val streetAddress = "street_address"
        const val locality = "locality"
        const val region = "region"
        const val postalCode = "postal_code"
        const val country = "country"
    }
}