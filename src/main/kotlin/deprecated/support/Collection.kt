package deprecated.support

import deprecated.client.metadata.ResponseType

fun Collection<ResponseType>.exactly(expected: ResponseType): Boolean =
    this.size == 1 && this.contains(expected)