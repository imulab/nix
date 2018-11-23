package io.imulab.nix.constant

object StandardClaims {

    // string
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
    const val gender = "gender"
    const val birthdate = "birthdate"
    const val zoneinfo = "zoneinfo"
    const val locale = "locale"
    const val phoneNumber = "phone_number"

    // json object
    const val address = "address"

    // boolean
    const val emailVerified = "email_verified"
    const val phoneNumberVerified = "phone_number_verified"

    // number
    const val updatedAt = "updated_at"

    val allClaims: List<String> by lazy {
        val c = mutableListOf<String>()
        c.addAll(stringClaims)
        c.addAll(jsonObjectClaims)
        c.addAll(booleanClaims)
        c.addAll(numberClaims)
        return@lazy c
    }

    val stringClaims: List<String> = listOf(
        name, givenName, familyName, middleName, nickname, preferredUsername,
        profile, picture, website, email, gender, birthdate, zoneinfo, locale, phoneNumber
    )

    val jsonObjectClaims: List<String> = listOf(address)

    val booleanClaims: List<String> = listOf(emailVerified, phoneNumberVerified)

    val numberClaims: List<String> = listOf(updatedAt)
}