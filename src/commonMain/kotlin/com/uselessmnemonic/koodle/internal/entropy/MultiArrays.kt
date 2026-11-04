package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException

internal data class DecodedMultiArray(
    val bytesConsumed: Int,
    val totalSize: Int,
    val starts: IntArray,
    val sizes: IntArray,
)

/** Scalar equivalent of the reference `decode_multi_array` capability. */
internal fun decodeMultiArray(
    source: ByteArray,
    start: Int,
    end: Int,
    destination: ByteArray,
    destinationStart: Int,
    arrayCount: Int,
    workspace: EntropyWorkspace,
    scratchWorkspace: EntropyWorkspace,
): DecodedMultiArray {
    require(start >= 0 && end >= start && end <= source.size)
    require(destinationStart >= 0 && destinationStart <= destination.size)
    require(arrayCount > 0)
    if (end - start < 4) throw DecompressionException("Truncated multi-array payload")
    val controlByte = source[start].toInt() and 255
    if (controlByte and 0x80 == 0) throw DecompressionException("Missing multi-array marker")
    val fileCount = controlByte and 0x3f
    var input = start + 1
    var written = destinationStart
    val resultStarts = IntArray(arrayCount)
    val resultSizes = IntArray(arrayCount)

    if (fileCount == 0) {
        repeat(arrayCount) { array ->
            val header = readByteArrayHeader(source, input, end, destination.size - written)
            val consumed = header.headerSize + header.encodedSize
            resultStarts[array] = written
            resultSizes[array] = header.decodedSize
            decodeByteArray(
                source, input, input + consumed,
                destination, written, written + header.decodedSize,
                scratchWorkspace,
            )
            input += consumed
            written += header.decodedSize
        }
        return DecodedMultiArray(
            input - start, written - destinationStart, resultStarts, resultSizes,
        )
    }

    val sourcePositions = IntArray(fileCount)
    val sourceRemaining = IntArray(fileCount)
    var scratch = 0
    var totalSize = 0
    repeat(fileCount) { index ->
        val header = readByteArrayHeader(source, input, end, destination.size - destinationStart - totalSize)
        val consumed = header.headerSize + header.encodedSize
        scratchWorkspace.requireRange(scratch, header.decodedSize)
        decodeByteArray(
            source, input, input + consumed,
            scratchWorkspace.bytes, scratch, scratch + header.decodedSize,
            scratchWorkspace, scratch + header.decodedSize,
        )
        sourcePositions[index] = scratch
        sourceRemaining[index] = header.decodedSize
        scratch += header.decodedSize
        totalSize += header.decodedSize
        input += consumed
    }
    workspace.requireRange(destinationStart, totalSize)
    if (end - input < 2) throw DecompressionException("Truncated multi-array control")
    val control = (source[input].toInt() and 255) or ((source[input + 1].toInt() and 255) shl 8)
    input += 2

    val indexHeader = readByteArrayHeader(source, input, end, totalSize)
    val indexCount = indexHeader.decodedSize
    if (indexCount < arrayCount) throw DecompressionException("Too few multi-array indexes")
    val combined = control and 0x8000 != 0
    val lengthCount = if (combined) indexCount else indexCount - arrayCount
    val lengthStart = scratch
    val indexStart = lengthStart + indexCount
    val metadataEnd = indexStart + indexCount
    scratchWorkspace.requireRange(lengthStart, indexCount * 2)

    val indexConsumed = indexHeader.headerSize + indexHeader.encodedSize
    decodeByteArray(
        source, input, input + indexConsumed,
        scratchWorkspace.bytes, indexStart, indexStart + indexCount,
        scratchWorkspace, metadataEnd,
    )
    input += indexConsumed
    if (combined) {
        repeat(indexCount) { index ->
            val value = scratchWorkspace.bytes[indexStart + index].toInt() and 255
            scratchWorkspace.bytes[lengthStart + index] = (value ushr 4).toByte()
            scratchWorkspace.bytes[indexStart + index] = (value and 15).toByte()
        }
    } else {
        val lengthHeader = readByteArrayHeader(source, input, end, lengthCount)
        if (lengthHeader.decodedSize != lengthCount) {
            throw DecompressionException("Multi-array length stream has wrong size")
        }
        val lengthConsumed = lengthHeader.headerSize + lengthHeader.encodedSize
        decodeByteArray(
            source, input, input + lengthConsumed,
            scratchWorkspace.bytes, lengthStart, lengthStart + lengthCount,
            scratchWorkspace, metadataEnd,
        )
        input += lengthConsumed
        repeat(lengthCount) { index ->
            if ((scratchWorkspace.bytes[lengthStart + index].toInt() and 255) > 16) {
                throw DecompressionException("Invalid multi-array length width")
            }
        }
    }

    val bitBytes = control and 0x3fff
    if (bitBytes > end - input) throw DecompressionException("Truncated multi-array bitstream")
    val bitEnd = input + bitBytes
    var forwardBits = 0
    var backwardBits = 0
    fun readBits(count: Int, backwards: Boolean): Int {
        if (forwardBits + backwardBits > bitBytes * 8 - count) {
            throw DecompressionException("Multi-array bitstreams overlap")
        }
        var value = 0
        repeat(count) {
            val position = if (backwards) backwardBits++ else forwardBits++
            val byte = if (backwards) bitEnd - 1 - position / 8 else input + position / 8
            value = (value shl 1) or ((source[byte].toInt() ushr (7 - position % 8)) and 1)
        }
        return value
    }
    val lengths = IntArray(lengthCount)
    var length = 0
    while (length + 1 < lengthCount) {
        val forwardWidth = scratchWorkspace.bytes[lengthStart + length].toInt() and 255
        val backwardWidth = scratchWorkspace.bytes[lengthStart + length + 1].toInt() and 255
        lengths[length++] = (1 shl forwardWidth) or readBits(forwardWidth, backwards = false)
        lengths[length++] = (1 shl backwardWidth) or readBits(backwardWidth, backwards = true)
    }
    if (length < lengthCount) {
        val width = scratchWorkspace.bytes[lengthStart + length].toInt() and 255
        lengths[length] = (1 shl width) or readBits(width, backwards = false)
    }

    var indexPosition = 0
    var lengthPosition = 0
    repeat(arrayCount) { array ->
        resultStarts[array] = written
        while (true) {
            if (indexPosition >= indexCount) throw DecompressionException("Truncated multi-array indexes")
            val sourceIndex = scratchWorkspace.bytes[indexStart + indexPosition++].toInt() and 255
            if (sourceIndex == 0) break
            if (sourceIndex !in 1..fileCount || lengthPosition >= lengthCount) {
                throw DecompressionException("Invalid multi-array source index")
            }
            val count = lengths[lengthPosition++]
            val entropyArray = sourceIndex - 1
            if (count > sourceRemaining[entropyArray] || count > destination.size - written) {
                throw DecompressionException("Multi-array interval exceeds its source")
            }
            scratchWorkspace.bytes.copyInto(
                destination, written,
                sourcePositions[entropyArray], sourcePositions[entropyArray] + count,
            )
            sourcePositions[entropyArray] += count
            sourceRemaining[entropyArray] -= count
            written += count
        }
        if (combined) lengthPosition++ // Each terminator owns an unused length nibble.
        resultSizes[array] = written - resultStarts[array]
    }
    if (indexPosition != indexCount || lengthPosition != lengthCount ||
        sourceRemaining.any { it != 0 } || written - destinationStart != totalSize
    ) {
        throw DecompressionException("Multi-array streams were not consumed exactly")
    }
    return DecodedMultiArray(
        bitEnd - start, totalSize, resultStarts, resultSizes,
    )
}
