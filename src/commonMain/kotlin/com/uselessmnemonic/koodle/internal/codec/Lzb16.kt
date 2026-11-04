package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException

import com.uselessmnemonic.koodle.internal.DecodeHistory

/** Decodes one bounded quantum; framing and I/O remain the caller's responsibility. */
internal fun decodeLzb16(
    input: ByteArray,
    inputSize: Int,
    output: ByteArray,
    outputSize: Int,
    history: DecodeHistory,
) {
    var position = 0
    var written = 0
    fun byte(): Int {
        if (position == inputSize) throw DecompressionException("Truncated LZB16 command")
        return input[position++].toInt() and 0xff
    }
    fun extension(): Int {
        val first = byte()
        return if (first < 0xc0) first else ((first and 0x3f) shl 8) or byte()
    }
    fun distance(): Int = byte() or (byte() shl 8)
    fun emit(value: Byte) {
        output[written++] = value
        history.append(value)
    }
    while (written < outputSize) {
        val control = byte()
        var literals = control and 15
        if (literals == 15) literals += extension()
        literals = minOf(literals, outputSize - written)
        if (literals > inputSize - position) throw DecompressionException("Truncated LZB16 literals")
        repeat(literals) { emit(input[position++]) }
        if (written == outputSize) break
        val code = control ushr 4
        val length: Int
        val offset: Int
        if (code < 15) {
            length = code + 4
            offset = distance()
        } else {
            val extra = byte()
            if (extra and 0x80 != 0) {
                val base = ((extra ushr 3) and 15) + 4
                length = base + if (base == 19) extension() else 0
                offset = extra and 7
            } else {
                offset = distance()
                length = 19 + extra + if (extra == 127) extension() else 0
            }
        }
        if (length > outputSize - written) throw DecompressionException("LZB16 match exceeds quantum output")
        // Read after each write: overlapping matches expand forward, unlike bulk copy.
        repeat(length) { emit(history.previous(offset)) }
    }
    if (position != inputSize) throw DecompressionException("Unused bytes in LZB16 quantum")
}
