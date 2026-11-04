@file:OptIn(kotlin.experimental.ExperimentalNativeApi::class)

package com.uselessmnemonic.koodle.internal

import kotlin.native.getIntAt

// Both configured Kotlin/Native ARM64 targets are little-endian. Revisit this
// implementation before adding a target with a different byte order.
internal actual fun ByteArray.readIntLe(index: Int): Int = getIntAt(index)
