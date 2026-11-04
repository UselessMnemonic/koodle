package com.uselessmnemonic.koodle.internal

/** Unaligned, bounds-checked little-endian load. Platform APIs stay internal. */
internal expect fun ByteArray.readIntLe(index: Int): Int
