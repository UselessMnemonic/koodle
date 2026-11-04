package com.uselessmnemonic.koodle

private inline fun <reified T : Throwable> fails(block: () -> Unit) {
    try { block() } catch (error: Throwable) {
        check(error is T) { "Expected ${T::class}, got $error" }
        return
    }
    error("Expected ${T::class}")
}

/** Dependency-free regression checks, shared by JVM and Native. */
public fun main() {
    val payload = byteArrayOf(1, 2, 3, 4, 5)
    val encoded = byteArrayOf(0x4c, 6) + payload
    check(decompress(encoded, 5).contentEquals(payload))
    for (kind in listOf(2, 5, 6, 10, 11, 12)) {
        check(decompress(byteArrayOf(0xcc.toByte(), kind.toByte()) + payload, 5).contentEquals(payload))
    }
    // Every small input/output chunk combination, including a header split across calls.
    for (inputChunk in 1..encoded.size) for (outputChunk in 1..6) {
        val decoder: Decoder = OozDecoder(5)
        var consumed = 0
        var written = 0
        val collected = ByteArray(5)
        var calls = 0
        while (true) {
            check(++calls < 30) { "Decoder made no progress" }
            val end = minOf(encoded.size, consumed + inputChunk)
            val out = ByteArray(outputChunk)
            val result = decoder.decode(encoded, out, consumed, end, endOfInput = end == encoded.size)
            out.copyInto(collected, written, 0, result.bytesWritten)
            consumed += result.bytesConsumed
            written += result.bytesWritten
            if (result.status == DecodeStatus.FINISHED) break
        }
        check(consumed == encoded.size && written == 5 && collected.contentEquals(payload))
        check(decoder.decode(encoded, ByteArray(1)).bytesConsumed == 0)
    }
    // Header cadence is 256 KiB, including codec types with 16 KiB quanta.
    for (kind in listOf(2, 6)) {
        val first = ByteArray(0x40000) { 0xab.toByte() }
        val second = ByteArray(31) { 0xcd.toByte() }
        val input = byteArrayOf(0x4c, kind.toByte()) + first + byteArrayOf(0x4c, kind.toByte()) + second
        check(decompress(input, first.size + second.size).contentEquals(first + second))
    }
    val framed = byteArrayOf(99) + encoded + byteArrayOf(88)
    val destination = ByteArray(9) { 77 }
    check(decompressInto(framed, destination, 2, 1, framed.size - 1, 5) == 5)
    check(destination.contentEquals(byteArrayOf(77, 77) + payload + byteArrayOf(77, 77)))
    val trailing = OozDecoder(5).decode(encoded + byteArrayOf(99), ByteArray(5), endOfInput = true)
    check(trailing == DecodeResult(encoded.size, 5, DecodeStatus.FINISHED))
    for (cut in 0 until encoded.size) {
        fails<DecompressionException> { decompress(encoded.copyOf(cut), 5) }
    }
    fails<DecompressionException> { decompress(byteArrayOf(0x4d, 6), 1) }
    fails<DecompressionException> { decompress(byteArrayOf(0x5c, 6), 1) }
    fails<DecompressionException> { decompress(byteArrayOf(0x4c, 3), 1) }
    fails<DecompressionException> { decompress(byteArrayOf(0x8c.toByte(), 6), 1) }
    fails<DecompressionException> { decompress(byteArrayOf(0x8c.toByte(), 6, 0, 0, 0), 1) }
    fails<UnsupportedOperationException> { decompress(byteArrayOf(0x4c, 0x86.toByte()), 1) }
    fails<IllegalArgumentException> { decompressInto(encoded, encoded) }
    fails<IllegalArgumentException> { decompressInto(encoded, ByteArray(3), 2, outputSize = Int.MAX_VALUE) }
    fails<IllegalArgumentException> { OozDecoder(-1) }
    val decoder = OozDecoder(5)
    fails<IllegalArgumentException> { decoder.decode(encoded, ByteArray(5), startIndex = -1) }
    check(decoder.decode(encoded, ByteArray(0)).status == DecodeStatus.NEEDS_OUTPUT)
    check(decoder.decode(ByteArray(0), ByteArray(5)).status == DecodeStatus.NEEDS_INPUT)
    check(decoder.decode(encoded, ByteArray(5)).status == DecodeStatus.FINISHED)
    val failed = OozDecoder(1)
    fails<DecompressionException> { failed.decode(byteArrayOf(0), ByteArray(1)) }
    fails<IllegalStateException> { failed.decode(encoded, ByteArray(1)) }
    check(OozDecoder(Long.MAX_VALUE).decode(encoded, ByteArray(5)).status == DecodeStatus.NEEDS_OUTPUT)
    check(decompress(ByteArray(0), 0).isEmpty())
    checkByteArrays()
    checkWholeMatches()
    checkLzb16()
    checkQuanta()
    println("Decoder regression checks passed")
}

private fun checkQuanta() {
    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
    fun fragmented(input: ByteArray, expected: ByteArray, inputChunk: Int, outputChunk: Int) {
        val decoder = OozDecoder(expected.size.toLong())
        val actual = ByteArray(expected.size)
        var consumed = 0
        var written = 0
        var calls = 0
        while (true) {
            check(++calls <= input.size + expected.size + 1)
            val end = minOf(input.size, consumed + inputChunk)
            val output = ByteArray(outputChunk + 2) { 99 }
            val result = decoder.decode(input, output, consumed, end, 1, output.size - 1, end == input.size)
            check(output.first() == 99.toByte() && output.last() == 99.toByte())
            output.copyInto(actual, written, 1, 1 + result.bytesWritten)
            consumed += result.bytesConsumed
            written += result.bytesWritten
            if (result.status == DecodeStatus.FINISHED) break
            check(result.bytesConsumed > 0 || result.bytesWritten > 0)
        }
        check(consumed == input.size && written == expected.size && actual.contentEquals(expected))
    }
    for (kind in listOf(2, 5, 6, 10, 11, 12)) {
        val large = kind in listOf(6, 10, 12)
        val fill = bytes(0x8c, kind) + (if (large) bytes(7, 255, 255, 0xab) else bytes(127, 255, 0xab))
        for (inputChunk in 1..fill.size) for (outputChunk in 1..9) {
            fragmented(fill, ByteArray(17) { 0xab.toByte() }, inputChunk, outputChunk)
        }
        for (cut in fill.indices) {
            fails<DecompressionException> { decompress(fill.copyOf(cut), 17) }
        }
    }
    val raw = bytes(0x8c, 2, 0xbf, 0xff, 1, 2, 3, 4, 5)
    for (inputChunk in 1..raw.size) for (outputChunk in 1..6) {
        fragmented(raw, bytes(1, 2, 3, 4, 5), inputChunk, outputChunk)
    }
    for (cut in raw.indices) fails<DecompressionException> { decompress(raw.copyOf(cut), 5) }
    // Mixed small quanta, a new block header after 16 quanta, then a large fill.
    var mixed = bytes(0x8c, 2)
    val expected = ByteArray(0x40000 + 9)
    repeat(16) { index ->
        if (index % 2 == 0) {
            mixed += bytes(0x7f, 0xff, index)
        } else {
            mixed += bytes(0xbf, 0xff) + ByteArray(0x4000) { index.toByte() }
        }
        expected.fill(index.toByte(), index * 0x4000, (index + 1) * 0x4000)
    }
    mixed += bytes(0x0c, 6, 7, 255, 255, 0xfe)
    expected.fill(0xfe.toByte(), 0x40000)
    check(decompress(mixed, expected.size).contentEquals(expected))
    fragmented(mixed, expected, 137, 211)
    // Large fill followed by a raw block exercises the reverse transition.
    val transition = bytes(0x8c, 6, 7, 255, 255, 42, 0x4c, 6, 7)
    fragmented(transition, ByteArray(0x40000) { 42 } + bytes(7), 1, 997)
    fails<DecompressionException> { decompress(bytes(0x8c, 6, 3, 255, 255), 1) }
    fails<DecompressionException> { decompress(bytes(0x8c, 6, 11, 255, 255), 1) }
    fails<DecompressionException> { decompress(bytes(0x8c, 2, 255, 255), 1) }
    fails<DecompressionException> { decompress(bytes(0x8c, 2, 63, 255), 1) }
    fails<DecompressionException> { decompress(bytes(0x8c, 2, 0, 0), 1) }
    // Payload size fields are big-endian, masked, and stored as size minus one.
    val parser = com.uselessmnemonic.koodle.internal.QuantumHeaderParser()
    parser.reset(large = true)
    check(parser.accept(0x04) == null)
    check(parser.accept(0x12) == null)
    check(parser.accept(0x34) == com.uselessmnemonic.koodle.internal.QuantumHeader.Compressed(0x1235))
    parser.reset(large = false)
    check(parser.accept(0x40) == null)
    check(parser.accept(0) == com.uselessmnemonic.koodle.internal.QuantumHeader.Compressed(1))
}
