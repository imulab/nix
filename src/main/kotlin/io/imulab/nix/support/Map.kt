package io.imulab.nix.support

import io.imulab.nix.client.metadata.GrantType
import io.imulab.nix.client.metadata.ResponseType
import io.imulab.nix.constant.ErrorCode
import io.imulab.nix.constant.Misc
import io.imulab.nix.constant.Param
import io.imulab.nix.error.InvalidRequestException

fun Map<String, String>.clientId(): String = this[Param.CLIENT_ID] ?: ""

fun Map<String, String>.mustClientId(): String = this[Param.CLIENT_ID] ?: throw InvalidRequestException(
    subCode = ErrorCode.Sub.MISSING_CLIENT_ID,
    message = "${Param.CLIENT_ID} required."
)

fun Map<String, String>.redirectUri(): String = this[Param.REDIRECT_URI] ?: ""

fun Map<String, String>.scopes(): Set<String> =
    this[Param.SCOPE]?.split(Misc.SPACE)?.filter { it.isNotBlank() }?.toSet() ?: emptySet()

fun Map<String, String>.responseTypes(): Set<ResponseType> = this[Param.RESPONSE_TYPE]
    ?.split(Misc.SPACE)
    ?.filter { it.isNotBlank() }
    ?.map { it.asOAuthEnum(Param.RESPONSE_TYPE, false) as ResponseType }
    ?.toSet() ?: emptySet()

fun Map<String, String>.mustResponseTypes(): Set<ResponseType> = this[Param.RESPONSE_TYPE]
    ?.split(Misc.SPACE)
    ?.filter { it.isNotBlank() }
    ?.map { it.asOAuthEnum(Param.RESPONSE_TYPE, false) as ResponseType }
    ?.toSet()
    ?: throw InvalidRequestException(
        subCode = ErrorCode.Sub.MISSING_RESPONSE_TYPE,
        message = "${Param.RESPONSE_TYPE} required.")

fun Map<String, String>.grantTypes(): Set<GrantType> = this[Param.GRANT_TYPE]
    ?.split(Misc.SPACE)
    ?.filter { it.isNotBlank() }
    ?.map { it.asOAuthEnum(Param.GRANT_TYPE, false) as GrantType }
    ?.toSet() ?: emptySet()

fun Map<String, String>.mustState(): String = this[Param.STATE]
    ?: throw InvalidRequestException(
        subCode = ErrorCode.Sub.MISSING_STATE,
        message = "${Param.STATE} required.")

fun Map<String, String>.mustStateWithEnoughEntropy(minEntropy: Int) = this[Param.STATE]?.also {
  if (it.length < minEntropy)
      throw throw InvalidRequestException(
          subCode = ErrorCode.Sub.INSUFFICIENT_NONCE_ENTROPY,
          message = "${Param.STATE} entropy less than $minEntropy.")
} ?: throw InvalidRequestException(
        subCode = ErrorCode.Sub.MISSING_STATE,
        message = "${Param.STATE} required.")

fun Map<String, String>.request(): String = this[Param.REQUEST] ?: ""

fun Map<String, String>.requestUri(): String = this[Param.REQUEST_URI] ?: ""