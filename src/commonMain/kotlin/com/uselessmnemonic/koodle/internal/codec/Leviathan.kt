package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.entropy.ByteEncoding
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace
import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

private data class LeviathanStreams(
    val literalsStart: Int,
    val literalsSize: Int,
    val commandsStart: Int,
    val commandsSize: Int,
    val offsets: IntArray,
    val lengths: IntArray,
)

internal fun decodeLeviathanChunk(
    input: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputSize: Int,
    mode: Int, workspace: EntropyWorkspace, history: DecodeHistory,
) {
    if (mode !in 0..5) throw DecompressionException("Invalid Leviathan chunk mode")
    if (mode > 1) {
        throw UnsupportedOperationException("Leviathan multi-array literal modes are not supported yet")
    }
    if (end - start < 13) throw DecompressionException("Truncated Leviathan chunk")
    var source = start
    var destination = outputStart
    if (outputStart == 0 && !history.hasCodecOutput) {
        if (outputSize < 8 || end - source < 8) throw DecompressionException("Truncated Leviathan prefix")
        input.copyInto(output, destination, source, source + 8)
        source += 8
        destination += 8
    }
    val streams = readLeviathanStreams(input, source, end, outputSize, workspace)
    runLeviathanCommands(
        output, destination, outputStart + outputSize, mode,
        workspace.bytes, streams, history,
    )
}

private fun readLeviathanStreams(
    input: ByteArray, start: Int, end: Int, outputSize: Int, workspace: EntropyWorkspace,
): LeviathanStreams {
    var source = start
    var scratch = 0
    var scaling = 0
    fun decode(capacity: Int, name: String): Pair<Int, Int> {
        val streamStart = source
        val expected = readByteArrayHeader(input, source, end, capacity)
        workspace.requireRange(scratch, expected.decodedSize)
        val header = try {
            decodeByteArray(
                input, source, end, workspace.bytes, scratch, scratch + expected.decodedSize,
                workspace, scratch + expected.decodedSize,
            )
        } catch (error: DecompressionException) {
            throw DecompressionException(
                "Invalid Leviathan $name stream at ${streamStart - start}: ${error.message}",
            )
        }
        val decodedStart = scratch
        source += header.headerSize + header.encodedSize
        scratch += header.decodedSize
        return decodedStart to header.decodedSize
    }

    var extraStart = -1
    if (source >= end) throw DecompressionException("Missing Leviathan offset stream")
    if (input[source].toInt() and 0x80 != 0) {
        scaling = (input[source++].toInt() and 255) - 127
    }
    if (readByteArrayHeader(input, source, end, outputSize / 3).encoding == ByteEncoding.RECURSIVE) {
        throw UnsupportedOperationException("Recursive Leviathan packed-offset streams are not supported yet")
    }
    val (offsetStart, offsetCount) = decode(outputSize / 3, "offset")
    if (scaling != 0 && scaling != 1) {
        val extra = decode(offsetCount, "offset-low")
        if (extra.second != offsetCount) throw DecompressionException("Mismatched Leviathan offset streams")
        extraStart = extra.first
    }
    val (lengthStart, lengthCount) = decode(outputSize / 5, "length")
    val (literalStart, literalCount) = decode(outputSize, "literal")
    if (source >= end) throw DecompressionException("Missing Leviathan command stream")
    if (input[source].toInt() and 0x80 != 0) {
        if ((input[source].toInt() and 255) == 0x83) {
            throw UnsupportedOperationException("Leviathan multi-array commands are not supported yet")
        }
        throw DecompressionException("Invalid Leviathan command marker")
    }
    val (commandStart, commandCount) = decode(outputSize, "command")

    val unpacked = unpackOffsets(
        workspace.bytes,
        offsetStart, offsetCount,
        offsetLowBitsStart = extraStart, offsetScale = scaling,
        lengthStart, lengthCount,
        input, source, end, "Leviathan",
    )
    return LeviathanStreams(
        literalStart, literalCount, commandStart, commandCount,
        unpacked.offsets, unpacked.lengths,
    )
}

private fun runLeviathanCommands(
    output: ByteArray, start: Int, end: Int, mode: Int,
    scratch: ByteArray, streams: LeviathanStreams, history: DecodeHistory,
) {
    var destination = start
    var literal = streams.literalsStart
    val literalsEnd = literal + streams.literalsSize
    var offsetIndex = 0
    var lengthFront = 0
    var lengthBack = streams.lengths.size
    val recent = IntArray(16)
    for (index in 8..14) recent[index] = -8
    var lastOffset = -8

    fun previous(reference: Int): Byte =
        if (reference >= 0) output[reference] else history.previous(-reference)
    fun copyLiterals(count: Int) {
        if (count > literalsEnd - literal || count > end - destination) {
            throw DecompressionException("Leviathan literal run exceeds its stream")
        }
        repeat(count) {
            val value = scratch[literal++].toInt() and 255
            output[destination] = if (mode == 0) {
                val reference = destination + lastOffset
                if (reference >= destination) throw DecompressionException("Invalid Leviathan literal reference")
                (value + (previous(reference).toInt() and 255)).toByte()
            } else value.toByte()
            destination++
        }
    }

    repeat(streams.commandsSize) { commandIndex ->
        val command = scratch[streams.commandsStart + commandIndex].toInt() and 255
        val recentIndex = command ushr 5
        var matchLength = (command and 7) + 2
        var literalLength = (command ushr 3) and 3
        if (literalLength == 3) {
            if (lengthFront >= lengthBack) throw DecompressionException("Missing Leviathan literal length")
            literalLength = streams.lengths[lengthFront++] and 0xffffff
        }
        copyLiterals(literalLength)
        recent[15] = streams.offsets.getOrElse(offsetIndex) { 0 }
        val offset = recent[recentIndex + 8]
        recent.copyInto(recent, recentIndex + 1, recentIndex, recentIndex + 8)
        recent[8] = offset
        lastOffset = offset
        if (recentIndex == 7) {
            if (offsetIndex >= streams.offsets.size) throw DecompressionException("Missing Leviathan offset")
            offsetIndex++
        }
        if (matchLength == 9) {
            if (lengthFront >= lengthBack) throw DecompressionException("Missing Leviathan match length")
            matchLength = streams.lengths[--lengthBack] + 6
        }
        if (matchLength > end - destination) throw DecompressionException("Leviathan match exceeds output")
        repeat(matchLength) {
            val reference = destination + lastOffset
            if (reference >= destination) throw DecompressionException("Invalid Leviathan match offset")
            output[destination++] = previous(reference)
        }
    }
    if (offsetIndex != streams.offsets.size || lengthFront != lengthBack) {
        throw DecompressionException("Unused Leviathan command metadata")
    }
    copyLiterals(end - destination)
    if (literal != literalsEnd) throw DecompressionException("Unused Leviathan literals")
}
