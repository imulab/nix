package io.imulab.nix.support

import io.imulab.nix.constant.Error

/**
 * General interface for all OAuth options related enums to implement.
 */
interface OAuthEnum {
    /**
     * Value defined in OAuth and Open ID Connect documentation.
     */
    val specValue: String
}

/**
 * Parse any String which is believed to be the [OAuthEnum.specValue] of an enumeration to
 * that enumeration object.
 *
 * @return a parsed enumeration whose spec value is equal (depending on value of [ignoreCase]) to [this].
 */
inline fun <reified T> String.asOAuthEnum(paramName: String, ignoreCase: Boolean = false): T
        where T: Enum<T>, T: OAuthEnum {
    return enumValues<T>().find { it.specValue.equals(this, ignoreCase) }
        ?: throw Error.Enum.invalid(paramName)
}