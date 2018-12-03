package io.imulab.nix

import org.spekframework.spek2.dsl.GroupBody
import org.spekframework.spek2.dsl.Skip
import org.spekframework.spek2.dsl.TestBody
import org.spekframework.spek2.style.specification.Suite
import org.spekframework.spek2.style.specification.describe

fun GroupBody.given(description: String, skip: Skip = Skip.No, body: Suite.() -> Unit) {
    describe("Given: $description", skip, body)
}

fun Suite.`when`(description: String, skip: Skip = Skip.No, body: Suite.() -> Unit) {
    describe("When: $description", skip, body)
}

fun Suite.then(description: String, skip: Skip = Skip.No, body: TestBody.() -> Unit) {
    it("Then $description", skip, body)
}