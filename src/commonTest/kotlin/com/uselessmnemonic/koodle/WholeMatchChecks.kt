package com.uselessmnemonic.koodle

import com.uselessmnemonic.koodle.internal.QuantumHeader
import com.uselessmnemonic.koodle.internal.QuantumHeaderParser

private inline fun <reified T : Throwable> rejects(block: () -> Unit) {
    try { block() } catch (error: Throwable) {
        check(error is T) { "Expected ${T::class}, got $error" }
        return
    }
    error("Expected ${T::class}")
}

internal fun checkWholeMatches() {
    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
    fun match(distance: Long): ByteArray {
        if (distance <= 32768) {
            val encoded = (distance + 32767).toInt()
            return bytes(0x3f, 255, encoded ushr 8, encoded and 255)
        }
        val adjusted = distance - 32769
        val low = (adjusted and 32767).toInt()
        var high = adjusted ushr 15
        val result = mutableListOf<Byte>(0x3f, -1, (low ushr 8).toByte(), low.toByte())
        while (high >= 128) {
            result += (high and 127).toByte()
            high = (high ushr 7) - 1
        }
        result += (high + 128).toByte()
        return result.toByteArray()
    }
    val parser = QuantumHeaderParser()
    parser.reset(large = false)
    for (distance in listOf(1L, 32768L, 32769L, 65536L, 65537L, 4227073L, Int.MAX_VALUE.toLong(), Long.MAX_VALUE)) {
        val encoded = match(distance)
        encoded.dropLast(1).forEach { check(parser.accept(it) == null) }
        check(parser.accept(encoded.last()) == QuantumHeader.WholeMatch(distance))
    }
    rejects<DecompressionException> {
        (bytes(0x3f, 255, 0, 0) + ByteArray(20)).forEach { parser.accept(it) }
    }
    val seed = ByteArray(0x4000) { (it % 251).toByte() }
    for (kind in listOf(2, 5, 11)) for (distance in listOf(1, 3, 8, 0x4000)) {
        val input = bytes(0x8c, kind, 0xbf, 255) + seed + match(distance.toLong())
        val expected = seed.toMutableList()
        repeat(23) { expected += expected[expected.size - distance] }
        check(decompress(input, expected.size).contentEquals(expected.toByteArray()))
        for (inputChunk in listOf(1, 7, input.size)) for (outputChunk in listOf(1, 13, 8192)) {
            val decoder = OozDecoder(expected.size.toLong())
            val actual = ByteArray(expected.size)
            var consumed = 0
            var written = 0
            while (true) {
                val end = minOf(input.size, consumed + inputChunk)
                val out = ByteArray(outputChunk + 2) { 77 }
                val result = decoder.decode(input, out, consumed, end, 1, out.size - 1, end == input.size)
                check(out.first() == 77.toByte() && out.last() == 77.toByte())
                out.copyInto(actual, written, 1, 1 + result.bytesWritten)
                consumed += result.bytesConsumed
                written += result.bytesWritten
                if (result.status == DecodeStatus.FINISHED) break
                check(result.bytesConsumed > 0 || result.bytesWritten > 0)
            }
            check(consumed == input.size && actual.contentEquals(expected.toByteArray()))
        }
    }
    // Extended distances, a non-power-of-two ring, and exact capacity references.
    var prefix = bytes(0x8c, 2)
    val expected = mutableListOf<Byte>()
    repeat(5) { index ->
        prefix += bytes(0x7f, 255, index + 1)
        repeat(0x4000) { expected += (index + 1).toByte() }
    }
    for (distance in listOf(65536, 65537, 70000)) {
        val input = prefix + match(distance.toLong())
        val result = expected.toMutableList()
        repeat(17) { result += result[result.size - distance] }
        check(decompress(input, result.size, historyCapacity = 70000).contentEquals(result.toByteArray()))
        if (distance > 65536) rejects<UnsupportedOperationException> { decompress(input, result.size) }
        else check(decompress(input, result.size).contentEquals(result.toByteArray()))
    }
    // Every prefix of an extended header is truncated, not an unsupported feature.
    val header = match(65537)
    for (cut in header.indices) {
        rejects<DecompressionException> { decompress(prefix + header.copyOf(cut), expected.size + 1) }
    }
    rejects<DecompressionException> { decompress(bytes(0x8c, 2) + match(1), 1) }
    rejects<DecompressionException> { decompress(prefix + match(Long.MAX_VALUE), expected.size + 1) }
    rejects<IllegalArgumentException> { OozDecoder(1, historyCapacity = 65535) }
    rejects<IllegalArgumentException> { decompress(ByteArray(0), 0, historyCapacity = -1) }
    // Framing references can cross codec restarts; their output seeds new codec history.
    val raw = ByteArray(0x40000) { (it % 251).toByte() }
    val afterRestart = bytes(0x4c, 2) + raw + bytes(0x8c, 2) + match(8) + bytes(0, 2, 0, 1, 0)
    val restartedExpected = raw.toMutableList()
    repeat(0x4000) { restartedExpected += restartedExpected[restartedExpected.size - 8] }
    repeat(4) { restartedExpected += restartedExpected.last() }
    check(decompress(afterRestart, restartedExpected.size).contentEquals(restartedExpected.toByteArray()))
    // Failure poisons the decoder, including a history-capacity failure.
    val failed = OozDecoder((expected.size + 1).toLong())
    rejects<UnsupportedOperationException> { failed.decode(prefix + match(70000), ByteArray(expected.size + 1), endOfInput = true) }
    rejects<IllegalStateException> { failed.decode(ByteArray(0), ByteArray(1)) }
}
