package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace
import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

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
    val offsetScale = if (input[source].toInt() and 0x80 != 0) {
        (input[source++].toInt() and 255) - 127
    } else 0
    val (packedOffsetsStart, packedOffsetsSize) = decode(commandsSize)
    val offsetLowBitsStart = if (offsetScale > 1) {
        val (lowBitsStart, lowBitsSize) = decode(packedOffsetsSize)
        if (lowBitsSize != packedOffsetsSize) {
            throw DecompressionException("Kraken scaled offset streams have different sizes")
        }
        lowBitsStart
    } else {
        -1
    }
    val (packedLengthsStart, packedLengthsSize) = decode(outputSize ushr 2)

    val unpacked = unpackOffsets(
        workspace.bytes,
        packedOffsetsStart, packedOffsetsSize,
        offsetLowBitsStart, offsetScale,
        packedLengthsStart, packedLengthsSize,
        input, source, end, "Kraken",
    )
    return KrakenStreams(
        literalsStart, literalsSize, commandsStart, commandsSize,
        unpacked.offsets, unpacked.lengths,
    )
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
