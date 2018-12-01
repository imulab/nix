package io.imulab.nix.oauth.validation

/**
 * Interface to validate a value conforms to specification definition.
 *
 * This validator replaces the function which would otherwise be enforced by the use of Enum classes. However, because
 * we require extensibility by design, Enum classes cannot be used for this purpose. As a result, we have to defer to
 * the use of plain data types (such as, in this case, string) and require interfaces like this to validate values
 * manually.
 */
interface SpecDefinitionValidator {
    fun validate(value: String): String
}