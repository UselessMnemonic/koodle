package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace
import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

private data class MermaidStreams(
    val literalsStart: Int,
    val literalsSize: Int,
    val commandsStart: Int,
    val commandsSize: Int,
    val secondCommandStart: Int,
    val nearOffsets: IntArray,
    val farOffsetsFirst: IntArray,
    val farOffsetsSecond: IntArray,
    val lengthsStart: Int,
)

internal fun decodeMermaidChunk(
    input: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputSize: Int,
    mode: Int, workspace: EntropyWorkspace, history: DecodeHistory,
) {
    if (mode !in 0..1) throw DecompressionException("Invalid Mermaid chunk mode")
    if (end - start < 10) throw DecompressionException("Truncated Mermaid chunk")
    var source = start
    val needsPrefix = outputStart == 0 && !history.hasCodecOutput
    if (needsPrefix) {
        if (outputSize < 8 || end - source < 8) throw DecompressionException("Truncated Mermaid prefix")
        input.copyInto(output, outputStart, source, source + 8)
        source += 8
    }
    val streams = readMermaidStreams(
        input, source, end, outputSize, outputStart, workspace, history,
    )
    runMermaidCommands(
        input, end, output, outputStart, outputSize, mode, needsPrefix,
        workspace.bytes, streams, history,
    )
}

private fun readMermaidStreams(
    input: ByteArray, start: Int, end: Int, outputSize: Int, outputStart: Int,
    workspace: EntropyWorkspace, history: DecodeHistory,
): MermaidStreams {
    var source = start
    var scratch = 0
    fun decode(capacity: Int): Pair<Int, Int> {
        val expected = readByteArrayHeader(input, source, end, capacity)
        workspace.requireRange(scratch, expected.decodedSize)
        val header = decodeByteArray(
            input, source, end, workspace.bytes, scratch, scratch + expected.decodedSize,
            workspace, scratch + expected.decodedSize,
        )
        val decodedStart = scratch
        source += header.headerSize + header.encodedSize
        scratch += header.decodedSize
        return decodedStart to header.decodedSize
    }
    fun little(count: Int): Int {
        if (end - source < count) throw DecompressionException("Truncated Mermaid metadata")
        var value = 0
        repeat(count) { value = value or ((input[source++].toInt() and 255) shl (8 * it)) }
        return value
    }

    val (literalsStart, literalsSize) = decode(outputSize)
    val (commandsStart, commandsSize) = decode(outputSize)
    val secondCommandStart = if (outputSize <= 0x10000) commandsSize else little(2).also {
        if (it > commandsSize) throw DecompressionException("Invalid Mermaid command split")
    }
    val nearCount = little(2)
    val nearOffsets: IntArray
    if (nearCount == 0xffff) {
        val (highStart, highCount) = decode(outputSize ushr 1)
        val (lowStart, lowCount) = decode(outputSize ushr 1)
        if (lowCount != highCount) throw DecompressionException("Mismatched Mermaid offset streams")
        nearOffsets = IntArray(lowCount) { index ->
            (workspace.bytes[lowStart + index].toInt() and 255) or
                ((workspace.bytes[highStart + index].toInt() and 255) shl 8)
        }
    } else {
        if (nearCount > (end - source) / 2) throw DecompressionException("Truncated Mermaid near offsets")
        nearOffsets = IntArray(nearCount) { little(2) }
    }

    val farSizes = little(3)
    var firstCount = farSizes ushr 12
    var secondCount = farSizes and 0xfff
    if (firstCount == 0xfff) firstCount = little(2)
    if (secondCount == 0xfff) secondCount = little(2)
    val codecOffset = history.codecOutputCount + outputStart
    fun farOffsets(count: Int, absoluteOffset: Long): IntArray = IntArray(count) {
        var offset = little(3).toLong()
        if (absoluteOffset >= 0xbfffffL && offset >= 0xc00000L) {
            offset += little(1).toLong() shl 22
        }
        if (offset > absoluteOffset || offset > Int.MAX_VALUE) {
            throw DecompressionException("Invalid Mermaid far offset")
        }
        offset.toInt()
    }
    val firstFar = farOffsets(firstCount, codecOffset)
    val secondFar = farOffsets(secondCount, codecOffset + 0x10000)
    return MermaidStreams(
        literalsStart, literalsSize, commandsStart, commandsSize, secondCommandStart,
        nearOffsets, firstFar, secondFar, source,
    )
}

private fun runMermaidCommands(
    input: ByteArray, inputEnd: Int,
    output: ByteArray, outputStart: Int, outputSize: Int,
    mode: Int, needsPrefix: Boolean,
    scratch: ByteArray, streams: MermaidStreams, history: DecodeHistory,
) {
    var literal = streams.literalsStart
    val literalsEnd = literal + streams.literalsSize
    var nearIndex = 0
    var length = streams.lengthsStart
    var savedDistance = -8
    var remaining = outputSize
    var segmentStart = outputStart

    fun previous(reference: Int): Byte =
        if (reference >= 0) output[reference] else history.previous(-reference)
    fun copyLiterals(destinationStart: Int, count: Int, distance: Int): Int {
        if (count > literalsEnd - literal) throw DecompressionException("Mermaid literal stream is too short")
        var destination = destinationStart
        repeat(count) {
            val value = scratch[literal++].toInt() and 255
            output[destination] = if (mode == 0) {
                val reference = destination + distance
                if (reference >= destination) throw DecompressionException("Invalid Mermaid literal reference")
                (value + (previous(reference).toInt() and 255)).toByte()
            } else value.toByte()
            destination++
        }
        return destination
    }
    fun copyMatch(destinationStart: Int, count: Int, referenceStart: Int): Int {
        var destination = destinationStart
        var reference = referenceStart
        repeat(count) {
            if (reference >= destination) throw DecompressionException("Invalid Mermaid match offset")
            output[destination++] = previous(reference++)
        }
        return destination
    }
    fun readLength(base: Int): Int {
        if (length >= inputEnd) throw DecompressionException("Truncated Mermaid length stream")
        var value = input[length++].toInt() and 255
        if (value > 251) {
            if (inputEnd - length < 2) throw DecompressionException("Truncated Mermaid extended length")
            value += 4 * ((input[length].toInt() and 255) or ((input[length + 1].toInt() and 255) shl 8))
            length += 2
        }
        return value + base
    }

    repeat(2) { iteration ->
        if (remaining == 0) return@repeat
        val segmentSize = minOf(remaining, 0x10000)
        val segmentEnd = segmentStart + segmentSize
        var destination = segmentStart + if (needsPrefix && iteration == 0) 8 else 0
        var command = streams.commandsStart + if (iteration == 0) 0 else streams.secondCommandStart
        val commandEnd = streams.commandsStart +
            if (iteration == 0) streams.secondCommandStart else streams.commandsSize
        val farOffsets = if (iteration == 0) streams.farOffsetsFirst else streams.farOffsetsSecond
        var farIndex = 0
        while (command < commandEnd) {
            val value = scratch[command++].toInt() and 255
            when {
                value >= 24 -> {
                    val literalCount = value and 7
                    if (literalCount > segmentEnd - destination) {
                        throw DecompressionException("Mermaid literal run exceeds output")
                    }
                    destination = copyLiterals(destination, literalCount, savedDistance)
                    if (value ushr 7 == 0) {
                        if (nearIndex >= streams.nearOffsets.size) {
                            throw DecompressionException("Missing Mermaid near offset")
                        }
                        savedDistance = -streams.nearOffsets[nearIndex++]
                    }
                    val matchCount = (value ushr 3) and 15
                    if (matchCount > segmentEnd - destination) {
                        throw DecompressionException("Mermaid match exceeds output")
                    }
                    destination = copyMatch(destination, matchCount, destination + savedDistance)
                }
                value == 0 -> {
                    val count = readLength(64)
                    if (count > segmentEnd - destination) throw DecompressionException("Mermaid literal run exceeds output")
                    destination = copyLiterals(destination, count, savedDistance)
                }
                value == 1 -> {
                    val count = readLength(91)
                    if (nearIndex >= streams.nearOffsets.size) throw DecompressionException("Missing Mermaid near offset")
                    val distance = streams.nearOffsets[nearIndex++]
                    savedDistance = -distance
                    if (count > segmentEnd - destination) throw DecompressionException("Mermaid match exceeds output")
                    destination = copyMatch(destination, count, destination - distance)
                }
                else -> {
                    val count = if (value == 2) readLength(29) else value + 5
                    if (farIndex >= farOffsets.size) throw DecompressionException("Missing Mermaid far offset")
                    val reference = segmentStart - farOffsets[farIndex++]
                    savedDistance = reference - destination
                    if (count > segmentEnd - destination) throw DecompressionException("Mermaid match exceeds output")
                    destination = copyMatch(destination, count, reference)
                }
            }
        }
        if (farIndex != farOffsets.size) throw DecompressionException("Unused Mermaid far offsets")
        destination = copyLiterals(destination, segmentEnd - destination, savedDistance)
        segmentStart = segmentEnd
        remaining -= segmentSize
    }
    if (nearIndex != streams.nearOffsets.size) throw DecompressionException("Unused Mermaid near offsets")
    if (literal != literalsEnd) throw DecompressionException("Unused Mermaid literals")
    if (length != inputEnd) throw DecompressionException("Unused Mermaid length bytes")
}
