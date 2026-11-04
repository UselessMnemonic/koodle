package com.uselessmnemonic.koodle

internal fun checkLzb16() {
    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
    fun quantum(commands: ByteArray): ByteArray {
        val size = commands.size - 1
        return bytes(size ushr 8, size and 255) + commands
    }
    fun frame(commands: ByteArray): ByteArray = bytes(0x8c, 2) + quantum(commands)
    fun invalid(input: ByteArray, size: Int) {
        try { decompress(input, size) } catch (_: DecompressionException) { return }
        error("Expected invalid LZB16 data")
    }
    // Hand-built commands cover all length/distance forms from the format description.
    var commands = bytes(0x13, 97, 98, 99, 2, 0)
    val expected = mutableListOf<Byte>(97, 98, 99)
    fun match(length: Int, distance: Int) { repeat(length) { expected += expected[expected.size - distance] } }
    match(5, 2)
    commands += bytes(0xf0, 0x91)
    match(6, 1)
    commands += bytes(0x0f, 2) + ByteArray(17) { (0x40 + it).toByte() } + bytes(3, 0)
    repeat(17) { expected += (0x40 + it).toByte() }
    match(4, 3)
    commands += bytes(0xf0, 3, 20, 0)
    match(22, 20)
    commands += bytes(0xf0, 127, 7, 0, 5)
    match(151, 7)
    commands += bytes(0xf0, 0xfc, 0xc1, 0x39)
    match(332, 4)
    commands += bytes(9) + "12345678".encodeToByteArray()
    expected += "12345678".encodeToByteArray().toList()
    val encoded = frame(commands)
    check(decompress(encoded, expected.size).contentEquals(expected.toByteArray()))
    for (inputChunk in listOf(1, 2, 7, encoded.size)) for (outputChunk in listOf(1, 3, 31, expected.size)) {
        val decoder = OozDecoder(expected.size.toLong())
        var consumed = 0
        var written = 0
        val actual = ByteArray(expected.size)
        while (true) {
            val end = minOf(encoded.size, consumed + inputChunk)
            val out = ByteArray(outputChunk + 2) { 77 }
            val result = decoder.decode(encoded, out, consumed, end, 1, out.size - 1, end == encoded.size)
            check(out.first() == 77.toByte() && out.last() == 77.toByte())
            out.copyInto(actual, written, 1, 1 + result.bytesWritten)
            consumed += result.bytesConsumed
            written += result.bytesWritten
            if (result.status == DecodeStatus.FINISHED) break
            check(result.bytesConsumed > 0 || result.bytesWritten > 0)
        }
        check(consumed == encoded.size && actual.contentEquals(expected.toByteArray()))
    }
    for (cut in encoded.indices) invalid(encoded.copyOf(cut), expected.size)
    invalid(frame(bytes(0x13, 97, 98, 99, 9, 0)), 8) // before history
    invalid(frame(bytes(0x11, 97, 0, 0)), 6) // zero distance
    invalid(frame(bytes(0x11, 97, 1, 0)), 5) // match exceeds output
    invalid(frame(bytes(1, 97, 99)), 1) // unused payload
    invalid(frame(bytes(15, 0xc0)), 1) // truncated length extension
    invalid(frame(bytes(0xf1, 97, 127, 1, 0)), 200) // missing match extension
    // Two-byte literal extension, with no match after final literal run.
    val literal = ByteArray(300) { it.toByte() }
    check(decompress(frame(bytes(15, 0xc1, 0x1d) + literal), 300).contentEquals(literal))
    // All normal match codes.
    for (code in 0..14) {
        check(decompress(frame(bytes((code shl 4) or 1, 42, 1, 0)), code + 5)
            .contentEquals(ByteArray(code + 5) { 42 }))
    }
    // Raw/fill output feeds history. Ring wrap and distance 65535 across quanta.
    var prefix = bytes(0x8c, 2)
    repeat(5) { prefix += bytes(0x7f, 0xff, it + 1) }
    val historical = prefix + quantum(bytes(0, 255, 255))
    val decoded = decompress(historical, 5 * 0x4000 + 4)
    check(decoded.takeLast(4) == List(4) { 2.toByte() })
    val raw = ByteArray(0x40000) { (it % 251).toByte() }
    val continuation = bytes(0x4c, 2) + raw + bytes(0x0c, 2) + quantum(bytes(0, 1, 0))
    check(decompress(continuation, raw.size + 4).takeLast(4) == List(4) { raw.last() })
    val restarted = bytes(0x4c, 2) + raw + bytes(0x8c, 2) + quantum(bytes(0, 1, 0))
    invalid(restarted, raw.size + 4)
    // A compressed quantum followed by another compressed quantum shares history.
    val full = ByteArray(0x4000) { 65 }
    // 15 + 16369 literals would exceed the maximum compressed size, so seed a
    // literal and encode a long match of 16383 bytes instead.
    val first = bytes(0xf1, 65, 127, 1, 0, 0xff, 0x6d)
    val pair = frame(first) + quantum(bytes(0, 1, 0))
    check(decompress(pair, full.size + 4).contentEquals(full + bytes(65, 65, 65, 65)))
}
