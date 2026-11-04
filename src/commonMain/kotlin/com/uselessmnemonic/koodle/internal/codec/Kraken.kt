package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace
import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

private class KrakenVarBits(
    private val source: ByteArray,
    private val start: Int,
    private val end: Int,
) {
    private var forward = 0
    private var backward = 0

    fun forward(count: Int): Int = read(count, backwards = false)
    fun backward(count: Int): Int = read(count, backwards = true)

    private fun read(count: Int, backwards: Boolean): Int {
        if (count < 0 || forward + backward > (end - start) * 8 - count) {
            throw DecompressionException("Kraken variable-bit streams overlap")
        }
        var value = 0
        repeat(count) {
            val position = if (backwards) backward++ else forward++
            val index = if (backwards) end - 1 - position / 8 else start + position / 8
            value = (value shl 1) or ((source[index].toInt() ushr (7 - position % 8)) and 1)
        }
        return value
    }

    fun backwardGamma(): Int {
        var zeros = 0
        while (backward(1) == 0) {
            if (++zeros > 12) throw DecompressionException("Invalid Kraken length count")
        }
        return ((1 shl zeros) or backward(zeros)) - 1
    }

    fun distance(code: Int, backwards: Boolean): Int {
        val width = if (code < 0xf0) (code ushr 4) + 4 else code - 0xf0 + 4
        val low = if (backwards) backward(width) else forward(width)
        val value = (1 shl width) or low
        if (code < 0xf0) return value * 16 + (code and 15) - 248
        val tail = if (backwards) backward(12) else forward(12)
        return 8_322_816 + value * 4096 + tail
    }

    fun length(backwards: Boolean): Int {
        var zeros = 0
        while ((if (backwards) backward(1) else forward(1)) == 0) {
            if (++zeros > 12) throw DecompressionException("Invalid Kraken extended length")
        }
        val tail = if (backwards) backward(zeros + 6) else forward(zeros + 6)
        return (1 shl (zeros + 6)) + tail - 64
    }

    fun requireConsumed() {
        if ((forward + 7) / 8 + (backward + 7) / 8 != end - start) {
            throw DecompressionException("Unused Kraken variable-bit bytes")
        }
    }
}

private data class KrakenStreams(
    val literalsStart: Int,
    val literalsSize: Int,
    val commandsStart: Int,
    val commandsSize: Int,
    val offsets: IntArray,
    val lengths: IntArray,
)

internal fun decodeKrakenChunk(
    input: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputSize: Int,
    mode: Int, workspace: EntropyWorkspace, history: DecodeHistory,
) {
    if (mode !in 0..1) throw DecompressionException("Invalid Kraken chunk mode")
    if (end - start < 13) throw DecompressionException("Truncated Kraken chunk")
    var source = start
    var destination = outputStart
    if (outputStart == 0 && !history.hasCodecOutput) {
        if (end - source < 8 || outputSize < 8) throw DecompressionException("Truncated Kraken prefix")
        input.copyInto(output, destination, source, source + 8)
        source += 8
        destination += 8
    }
    if (source >= end) throw DecompressionException("Missing Kraken literal stream")
    if (input[source].toInt() and 0x80 != 0) {
        throw UnsupportedOperationException("Kraken excess-byte streams are not supported yet")
    }
    val streams = readKrakenStreams(input, source, end, outputSize, workspace)
    runKrakenCommands(
        output, destination, outputStart + outputSize, mode,
        workspace.bytes, streams, history,
    )
}

private fun readKrakenStreams(
    input: ByteArray, start: Int, end: Int, outputSize: Int, workspace: EntropyWorkspace,
): KrakenStreams {
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
        workspace.requireRange(0, scratch)
        return decodedStart to header.decodedSize
    }

    val (literalsStart, literalsSize) = decode(outputSize)
    val (commandsStart, commandsSize) = decode(outputSize)
    if (end - source < 3) throw DecompressionException("Truncated Kraken offset stream")
    if (input[source].toInt() and 0x80 != 0) {
        throw UnsupportedOperationException("Scaled Kraken offsets are not supported yet")
    }
    val (packedOffsetsStart, packedOffsetsSize) = decode(commandsSize)
    val (packedLengthsStart, packedLengthsSize) = decode(outputSize ushr 2)

    val bits = KrakenVarBits(input, source, end)
    val extendedLengthCount = bits.backwardGamma()
    if (extendedLengthCount > 512) throw DecompressionException("Too many Kraken extended lengths")
    val offsets = IntArray(packedOffsetsSize)
    repeat(packedOffsetsSize) { index ->
        val code = workspace.bytes[packedOffsetsStart + index].toInt() and 255
        offsets[index] = -bits.distance(code, backwards = index and 1 != 0)
    }
    val extended = IntArray(extendedLengthCount)
    repeat(extendedLengthCount) { index -> extended[index] = bits.length(index and 1 != 0) }
    val lengths = IntArray(packedLengthsSize)
    var extendedIndex = 0
    repeat(packedLengthsSize) { index ->
        var value = workspace.bytes[packedLengthsStart + index].toInt() and 255
        if (value == 255) {
            if (extendedIndex >= extended.size) throw DecompressionException("Missing Kraken extended length")
            value += extended[extendedIndex++]
        }
        lengths[index] = value + 3
    }
    if (extendedIndex != extended.size) throw DecompressionException("Unused Kraken extended lengths")
    bits.requireConsumed()
    return KrakenStreams(literalsStart, literalsSize, commandsStart, commandsSize, offsets, lengths)
}

private fun runKrakenCommands(
    output: ByteArray, start: Int, end: Int, mode: Int,
    scratch: ByteArray, streams: KrakenStreams, history: DecodeHistory,
) {
    var destination = start
    var literal = streams.literalsStart
    val literalsEnd = literal + streams.literalsSize
    var offsetIndex = 0
    var lengthIndex = 0
    val recent = IntArray(7)
    recent[3] = -8
    recent[4] = -8
    recent[5] = -8
    var lastOffset = -8

    repeat(streams.commandsSize) { commandIndex ->
        val command = scratch[streams.commandsStart + commandIndex].toInt() and 255
        var literalLength = command and 3
        val recentIndex = command ushr 6
        var matchLength = (command ushr 2) and 15
        if (literalLength == 3) {
            if (lengthIndex >= streams.lengths.size) throw DecompressionException("Missing Kraken literal length")
            literalLength = streams.lengths[lengthIndex++]
        }
        recent[6] = streams.offsets.getOrElse(offsetIndex) { 0 }
        if (literalLength > literalsEnd - literal || literalLength > end - destination) {
            throw DecompressionException("Kraken literal run exceeds its stream")
        }
        repeat(literalLength) {
            val value = scratch[literal++].toInt() and 255
            output[destination] = if (mode == 0) {
                val reference = destination + lastOffset
                if (reference >= destination) {
                    throw DecompressionException("Invalid Kraken literal reference")
                }
                val previous = if (reference >= 0) output[reference] else history.previous(-reference)
                (value + (previous.toInt() and 255)).toByte()
            } else value.toByte()
            destination++
        }
        val selected = recentIndex + 3
        val offset = recent[selected]
        recent.copyInto(recent, recentIndex + 1, recentIndex, recentIndex + 3)
        recent[3] = offset
        lastOffset = offset
        if (recentIndex == 3) {
            if (offsetIndex >= streams.offsets.size) throw DecompressionException("Missing Kraken offset")
            offsetIndex++
        }
        matchLength = if (matchLength == 15) {
            if (lengthIndex >= streams.lengths.size) throw DecompressionException("Missing Kraken match length")
            14 + streams.lengths[lengthIndex++]
        } else matchLength + 2
        if (matchLength > end - destination) throw DecompressionException("Kraken match exceeds output")
        val match = destination + lastOffset
        if (match >= destination) throw DecompressionException("Invalid Kraken match offset")
        repeat(matchLength) {
            val reference = destination + lastOffset
            output[destination] = if (reference >= 0) output[reference] else history.previous(-reference)
            destination++
        }
    }
    if (offsetIndex != streams.offsets.size || lengthIndex != streams.lengths.size) {
        throw DecompressionException("Unused Kraken command metadata")
    }
    val finalLength = end - destination
    if (finalLength != literalsEnd - literal) throw DecompressionException("Kraken literal stream has wrong size")
    repeat(finalLength) {
        val value = scratch[literal++].toInt() and 255
        output[destination] = if (mode == 0) {
            val reference = destination + lastOffset
            if (reference >= destination) {
                throw DecompressionException("Invalid Kraken final literal reference")
            }
            val previous = if (reference >= 0) output[reference] else history.previous(-reference)
            (value + (previous.toInt() and 255)).toByte()
        } else value.toByte()
        destination++
    }
}
