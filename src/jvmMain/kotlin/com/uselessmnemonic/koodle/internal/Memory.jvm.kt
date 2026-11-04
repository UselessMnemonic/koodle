package com.uselessmnemonic.koodle.internal

import java.lang.invoke.MethodHandles
import java.nio.ByteOrder

private val littleEndianInts =
    MethodHandles.byteArrayViewVarHandle(IntArray::class.java, ByteOrder.LITTLE_ENDIAN)

internal actual fun ByteArray.readIntLe(index: Int): Int =
    littleEndianInts.get(this, index) as Int
