package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException

/** Shared 128 KiB chunk framing for Kraken, Mermaid/Selkie, and Leviathan.
 * Only raw and supported byte-array paths are implemented, not LZ commands.
 */
internal fun decodeStoredQuantum(input: ByteArray, inputSize: Int, output: ByteArray, outputSize: Int) {
    var source = 0
    var destination = 0
    while (destination < outputSize) {
        val count = minOf(0x20000, outputSize - destination)
        if (inputSize - source < 3) throw DecompressionException("Truncated large-quantum chunk header")
        val bits = ((input[source].toInt() and 255) shl 16) or
            ((input[source + 1].toInt() and 255) shl 8) or (input[source + 2].toInt() and 255)
        if (bits and 0x800000 == 0) {
            val header = decodeByteArray(input, source, inputSize, output, destination, destination + count)
            if (header.decodedSize != count) throw DecompressionException("Chunk output size mismatch")
            source += header.headerSize + header.encodedSize
        } else {
            source += 3
            val size = bits and 0x7ffff
            val mode = (bits ushr 19) and 15
            if (size > inputSize - source) throw DecompressionException("Truncated chunk payload")
            if (size > count) throw DecompressionException("Chunk payload exceeds output size")
            if (size < count) throw UnsupportedOperationException("LZ chunk commands are not supported yet")
            if (mode != 0) throw DecompressionException("Invalid raw chunk mode")
            input.copyInto(output, destination, source, source + size)
            source += size
        }
        destination += count
    }
    if (source != inputSize) throw DecompressionException("Unused bytes in large quantum")
}
