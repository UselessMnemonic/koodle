package com.uselessmnemonic.koodle

import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

private inline fun <reified T : Throwable> rejectsArray(block: () -> Unit) {
    try { block() } catch (error: Throwable) {
        check(error is T) { "Expected ${T::class}, got $error" }
        return
    }
    error("Expected ${T::class}")
}

internal fun checkByteArrays() {
    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
    fun be(value: Long, count: Int): ByteArray = ByteArray(count) { (value ushr (8 * (count - 1 - it))).toByte() }
    fun binary(value: Int, width: Int): String = value.toString(2).padStart(width, '0')
    fun pack(bits: String): ByteArray {
        val result = ByteArray((bits.length + 7) / 8)
        for (index in bits.indices) if (bits[index] == '1') {
            result[index / 8] = (result[index / 8].toInt() or (1 shl (7 - index % 8))).toByte()
        }
        return result
    }
    fun raw(payload: ByteArray, short: Boolean = false): ByteArray =
        be(payload.size.toLong() or (if (short) 0x8000L else 0L), if (short) 2 else 3) + payload
    fun encoded(payload: ByteArray, size: Int, kind: Int = 3, short: Boolean = false): ByteArray {
        return if (short) {
            be(0x800000L or (kind.toLong() shl 20) or ((size - payload.size - 1).toLong() shl 10) or payload.size.toLong(), 3) + payload
        } else {
            val n = size - 1
            bytes((kind shl 4) or (n ushr 14)) + be(((n.toLong() and 0x3fff) shl 18) or payload.size.toLong(), 4) + payload
        }
    }
    fun verify(input: ByteArray, expected: ByteArray) {
        val output = ByteArray(expected.size + 4) { 99 }
        val source = bytes(77) + input + bytes(88)
        val result = decodeByteArray(source, 1, source.size, output, 2, output.size - 2)
        check(result.headerSize + result.encodedSize == input.size)
        check(result.decodedSize == expected.size)
        check(output.contentEquals(bytes(99, 99) + expected + bytes(99, 99)))
        for (cut in input.indices) {
            rejectsArray<DecompressionException> { decodeByteArray(input, 0, cut, ByteArray(expected.size), 0, expected.size) }
        }
    }
    verify(raw(bytes(1, 2, 3)), bytes(1, 2, 3))
    verify(raw(bytes(1, 2, 3), short = true), bytes(1, 2, 3))
    verify(raw(ByteArray(0)), ByteArray(0))
    verify(raw(ByteArray(4095) { it.toByte() }, short = true), ByteArray(4095) { it.toByte() })
    verify(encoded(bytes(0xab), 31, short = true), ByteArray(31) { 0xab.toByte() })
    verify(encoded(bytes(0xff), 262144), ByteArray(262144) { -1 })
    // Short command: copy 2 literals then 15 repeats, initial fill is zero.
    verify(encoded(bytes(0, 11, 22, 0xfd), 17), bytes(11, 22) + ByteArray(15))
    // Read commands backwards: change fill, then emit a short run.
    verify(encoded(bytes(0, 42, 0xff, 1), 15), ByteArray(15) { 42 })
    // Medium command: copy 3, repeat 70 (word = 4096 + 70*64 + 3).
    verify(encoded(bytes(0, 1, 2, 3, 0x83, 0x21), 73), bytes(1, 2, 3) + ByteArray(70))
    // Long fill: (0x0900 - 0x08ff)*128, following a fill-value change.
    verify(encoded(bytes(0, 0x80, 0, 9, 1), 128), ByteArray(128) { 0x80.toByte() })
    // Long literal command followed by a fill so compressed size is smaller.
    val literals = ByteArray(64) { (it + 1).toByte() }
    val longCopy = bytes(0) + literals + bytes(0xff, 0, 2)
    verify(encoded(longCopy, 79), literals + ByteArray(15))
    // cmd=0 copies fifteen literals. Reverse command ordering matters.
    val fifteen = ByteArray(15) { it.toByte() }
    verify(encoded(bytes(0) + fifteen + bytes(0xff, 0), 30), fifteen + ByteArray(15))
    // Raw nested array replaces the zero prefix; its tail remains command data.
    verify(encoded(raw(bytes(42), short = true) + bytes(0xff, 1), 15), ByteArray(15) { 42 })
    fun malformed(input: ByteArray, outputSize: Int) {
        rejectsArray<DecompressionException> { decodeByteArray(input, 0, input.size, ByteArray(outputSize), 0, outputSize) }
    }
    malformed(bytes(4, 0, 0), 1) // reserved raw header bits
    malformed(bytes(0x60, 0), 1) // reserved encoding
    malformed(encoded(ByteArray(0), 5), 5)
    malformed(encoded(bytes(0, 1), 3), 3) // missing fill value
    malformed(encoded(bytes(0, 9), 3), 3) // missing long-command byte
    malformed(encoded(bytes(0, 0xfd), 17), 17) // missing literals
    malformed(encoded(bytes(0, 0xff), 16), 16) // output undershoot
    malformed(encoded(bytes(0, 0xff), 14), 14) // output overshoot
    malformed(raw(bytes(1, 2)), 1) // caller capacity
    malformed(encoded(bytes(1, 2), 2), 2) // no compression in long header
    for (kind in listOf(1)) {
        val input = encoded(bytes(42), 31, kind)
        rejectsArray<UnsupportedOperationException> { decodeByteArray(input, 0, input.size, ByteArray(31), 0, 31) }
    }
    val malformedPacked = encoded(encoded(bytes(42), 20), 50)
    rejectsArray<DecompressionException> {
        decodeByteArray(malformedPacked, 0, malformedPacked.size, ByteArray(50), 0, 50)
    }
    fun packedFill(kind: Int): ByteArray {
        val literalCount = 150
        val nested = when (kind) {
            2, 4 -> {
                val table = pack("00" + binary(1, 8) + binary(42, 8))
                encoded(table, literalCount, kind)
            }
            3 -> encoded(bytes(42), literalCount, kind)
            else -> error("Unexpected nested kind")
        }
        return encoded(nested + ByteArray(10) { 0xf0.toByte() }, 300)
    }
    val packedExpected = ByteArray(300) { if (it % 30 < 15) 42 else 0 }
    for (kind in listOf(2, 3, 4)) verify(packedFill(kind), packedExpected)
    fun recursive(children: List<ByteArray>, outputSize: Int, interleaved: Boolean = false): ByteArray =
        encoded(
            bytes(children.size or if (interleaved) 0x80 else 0) +
                children.fold(ByteArray(0), ByteArray::plus),
            outputSize,
            5,
        )
    val recursiveFirst = encoded(bytes(7), 40)
    val recursiveSecondTable = pack("00" + binary(1, 8) + binary(42, 8))
    val recursiveSecond = encoded(recursiveSecondTable, 60, 2)
    val sequential = recursive(listOf(recursiveFirst, recursiveSecond), 100)
    verify(sequential, ByteArray(40) { 7 } + ByteArray(60) { 42 })
    val nestedSequential = recursive(listOf(recursive(listOf(recursiveFirst), 40)), 40)
    verify(nestedSequential, ByteArray(40) { 7 })
    var tooDeep = encoded(bytes(7), 1000)
    repeat(65) { tooDeep = recursive(listOf(tooDeep), 1000) }
    rejectsArray<DecompressionException> {
        decodeByteArray(tooDeep, 0, tooDeep.size, ByteArray(1000), 0, 1000)
    }
    val recursiveLiterals = recursive(listOf(encoded(bytes(42), 150)), 150)
    val recursivePackedRle = encoded(recursiveLiterals + ByteArray(10) { 0xf0.toByte() }, 300)
    verify(recursivePackedRle, packedExpected)
    rejectsArray<UnsupportedOperationException> {
        val input = recursive(listOf(recursiveFirst), 40, interleaved = true)
        decodeByteArray(input, 0, input.size, ByteArray(40), 0, 40)
    }
    for (count in listOf(0, 3, 127)) {
        val input = encoded(bytes(count) + ByteArray(5), 40, 5)
        rejectsArray<DecompressionException> {
            decodeByteArray(input, 0, input.size, ByteArray(40), 0, 40)
        }
    }
    val recursiveUndershoot = recursive(listOf(recursiveFirst), 41)
    rejectsArray<DecompressionException> {
        decodeByteArray(recursiveUndershoot, 0, recursiveUndershoot.size, ByteArray(41), 0, 41)
    }
    val recursiveTrailing = encoded(bytes(1) + recursiveFirst + bytes(99), 40, 5)
    rejectsArray<DecompressionException> {
        decodeByteArray(recursiveTrailing, 0, recursiveTrailing.size, ByteArray(40), 0, 40)
    }
    val recursiveUnsupported = recursive(listOf(encoded(bytes(1), 40, kind = 1)), 40)
    rejectsArray<UnsupportedOperationException> {
        decodeByteArray(recursiveUnsupported, 0, recursiveUnsupported.size, ByteArray(40), 0, 40)
    }
    val tooLargeNested = encoded(bytes(7), 0x40000)
    val workspaceOverflow = encoded(tooLargeNested + bytes(0), 0x40000)
    rejectsArray<DecompressionException> {
        decodeByteArray(workspaceOverflow, 0, workspaceOverflow.size, ByteArray(0x40000), 0, 0x40000)
    }
    val unsupportedNested = encoded(encoded(bytes(1), 100, kind = 1) + bytes(0xff), 100)
    rejectsArray<UnsupportedOperationException> {
        decodeByteArray(unsupportedNested, 0, unsupportedNested.size, ByteArray(100), 0, 100)
    }
    rejectsArray<IllegalArgumentException> { readByteArrayHeader(bytes(0, 0), -1, 2, 0) }

    fun framed(payload: ByteArray, kind: Int): ByteArray = bytes(0x8c, kind) + be((payload.size - 1).toLong(), 3) + payload
    // Short array headers are internal-only here: large chunk dispatch uses bit 23.
    val arrays = raw(ByteArray(0x20000) { (it % 251).toByte() }) + encoded(bytes(42), 19)
    val expected = ByteArray(0x20000) { (it % 251).toByte() } + ByteArray(19) { 42 }
    for (kind in listOf(6, 10, 12)) {
        check(decompress(framed(arrays, kind), expected.size).contentEquals(expected))
        check(decompress(framed(packedFill(2), kind), packedExpected.size).contentEquals(packedExpected))
        check(decompress(framed(sequential, kind), 100)
            .contentEquals(ByteArray(40) { 7 } + ByteArray(60) { 42 }))
        val input = framed(encoded(bytes(71), 123), kind)
        for (inputChunk in 1..input.size) for (outputChunk in listOf(1, 13, 123)) {
            val decoder = OozDecoder(123)
            var consumed = 0
            val actual = mutableListOf<Byte>()
            while (true) {
                val end = minOf(input.size, consumed + inputChunk)
                val output = ByteArray(outputChunk)
                val result = decoder.decode(input, output, consumed, end, endOfInput = end == input.size)
                consumed += result.bytesConsumed
                repeat(result.bytesWritten) { actual += output[it] }
                if (result.status == DecodeStatus.FINISHED) break
                check(result.bytesConsumed > 0 || result.bytesWritten > 0)
            }
            check(consumed == input.size && actual == List(123) { 71.toByte() })
        }
    }
    val plain = bytes(1, 2, 3, 4, 5)
    check(decompress(framed(be(0x800005, 3) + plain, 6), 5).contentEquals(plain))
    rejectsArray<DecompressionException> { decompress(framed(be(0x880005, 3) + plain, 6), 5) }
    rejectsArray<DecompressionException> { decompress(framed(raw(plain), 6), 6) }
    rejectsArray<DecompressionException> { decompress(framed(raw(plain) + bytes(99), 6), 5) }
    rejectsArray<UnsupportedOperationException> { decompress(framed(be(0x800001, 3) + bytes(0), 6), 5) }
    val full = framed(encoded(bytes(0xab), 0x20000) + encoded(bytes(0xcd), 0x20000), 6)
    check(decompress(full, 0x40000).contentEquals(ByteArray(0x20000) { 0xab.toByte() } + ByteArray(0x20000) { 0xcd.toByte() }))
    for (cut in full.indices) rejectsArray<DecompressionException> { decompress(full.copyOf(cut), 0x40000) }
}
