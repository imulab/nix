package io.imulab.nix.support

import io.imulab.nix.client.metadata.ResponseType

fun Collection<ResponseType>.exactly(expected: ResponseType): Boolean =
    this.size == 1 && this.contains(expected)