package io.imulab.nix.oidc.reserved

object StandardClaim {
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