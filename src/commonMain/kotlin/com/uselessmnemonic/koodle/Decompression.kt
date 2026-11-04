package com.uselessmnemonic.koodle

/**
 * Allocates exactly [outputSize] bytes and decodes Oodle framing into them.
 * [historyCapacity] bounds retained history independently of the output; see [OozDecoder].
 */
public fun decompress(
    source: ByteArray,
    outputSize: Int,
    historyCapacity: Int = 0x10000,
): ByteArray {
    require(outputSize >= 0) { "outputSize must be non-negative" }
    require(historyCapacity >= 0x10000) { "historyCapacity must be at least 65536 bytes" }
    return ByteArray(outputSize).also { decompressInto(source, it, historyCapacity = historyCapacity) }
}

/**
 * Decodes one Oodle stream into an exact-sized destination range, returning bytes written.
 * The enclosing container must supply [outputSize]. Source bounds are half-open.
 * Trailing input is ignored; use [OozDecoder] when consumed-input counts are needed.
 * Arrays must not alias. Bytes outside the destination range are preserved.
 * [historyCapacity] bounds retained stream history; see [OozDecoder].
 * Failures can leave partial output. The caller retains ownership of both arrays.
 *
 * @throws IllegalArgumentException for invalid ranges or aliased arrays.
 * @throws DecompressionException for malformed or truncated input.
 * @throws UnsupportedOperationException for unsupported blocks or insufficient history capacity.
 */
public fun decompressInto(
    source: ByteArray,
    destination: ByteArray,
    destinationOffset: Int = 0,
    startIndex: Int = 0,
    endIndex: Int = source.size,
    outputSize: Int = destination.size - destinationOffset,
    historyCapacity: Int = 0x10000,
): Int {
    require(destinationOffset >= 0 && destinationOffset <= destination.size) {
        "Invalid destination offset"
    }
    require(outputSize >= 0 && outputSize <= destination.size - destinationOffset) {
        "Invalid output size"
    }
    val result = OozDecoder(outputSize.toLong(), historyCapacity).decode(
        source, destination, startIndex, endIndex,
        destinationOffset, destinationOffset + outputSize, endOfInput = true,
    )
    check(result.status == DecodeStatus.FINISHED)
    return result.bytesWritten
}
