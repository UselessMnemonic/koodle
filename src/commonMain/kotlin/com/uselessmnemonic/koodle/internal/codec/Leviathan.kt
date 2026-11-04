package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace
import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray
import com.uselessmnemonic.koodle.internal.entropy.decodeMultiArray
import com.uselessmnemonic.koodle.internal.entropy.readByteArrayHeader

private data class LeviathanStreams(
    val literalStarts: IntArray,
    val literalSizes: IntArray,
    val commandStarts: IntArray,
    val commandSizes: IntArray,
    val commandCount: Int,
    val arenaEnd: Int,
    val offsets: IntArray,
    val lengths: IntArray,
)

internal fun decodeLeviathanChunk(
    input: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputSize: Int,
    mode: Int, workspace: EntropyWorkspace, codecScratch: EntropyWorkspace,
    history: DecodeHistory,
) {
    if (mode !in 0..5) throw DecompressionException("Invalid Leviathan chunk mode")
    if (end - start < 13) throw DecompressionException("Truncated Leviathan chunk")
    var source = start
    var destination = outputStart
    if (outputStart == 0 && !history.hasCodecOutput) {
        if (outputSize < 8 || end - source < 8) throw DecompressionException("Truncated Leviathan prefix")
        input.copyInto(output, destination, source, source + 8)
        source += 8
        destination += 8
    }
    val streams = readLeviathanStreams(input, source, end, outputSize, mode, workspace, codecScratch)
    runLeviathanCommands(
        output, destination, outputStart + outputSize, mode,
        workspace.bytes, streams, history,
    )
}

private fun readLeviathanStreams(
    input: ByteArray, start: Int, end: Int, outputSize: Int, mode: Int,
    workspace: EntropyWorkspace, codecScratch: EntropyWorkspace,
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
    val (offsetStart, offsetCount) = decode(outputSize / 3, "offset")
    if (scaling != 0 && scaling != 1) {
        val extra = decode(offsetCount, "offset-low")
        if (extra.second != offsetCount) throw DecompressionException("Mismatched Leviathan offset streams")
        extraStart = extra.first
    }
    val (lengthStart, lengthCount) = decode(outputSize / 5, "length")
    val literalArrayCount = when (mode) {
        0, 1 -> 1
        2 -> 2
        3 -> 4
        else -> 16
    }
    val literalStarts: IntArray
    val literalSizes: IntArray
    if (literalArrayCount == 1) {
        val literal = decode(outputSize, "literal")
        literalStarts = intArrayOf(literal.first)
        literalSizes = intArrayOf(literal.second)
    } else {
        val decoded = decodeMultiArray(
            input, source, end, workspace.bytes, scratch, literalArrayCount,
            workspace, codecScratch,
        )
        source += decoded.bytesConsumed
        scratch += decoded.totalSize
        literalStarts = decoded.starts
        literalSizes = decoded.sizes
    }
    if (source >= end) throw DecompressionException("Missing Leviathan command stream")
    val commandStarts: IntArray
    val commandSizes: IntArray
    val commandCount: Int
    if (input[source].toInt() and 0x80 != 0) {
        if ((input[source].toInt() and 255) == 0x83) {
            source++
            val decoded = decodeMultiArray(
                input, source, end, workspace.bytes, scratch, 8,
                workspace, codecScratch,
            )
            source += decoded.bytesConsumed
            scratch += decoded.totalSize
            commandStarts = decoded.starts
            commandSizes = decoded.sizes
            commandCount = decoded.totalSize
        } else {
            throw DecompressionException("Invalid Leviathan command marker")
        }
    } else {
        val command = decode(outputSize, "command")
        commandStarts = intArrayOf(command.first)
        commandSizes = intArrayOf(command.second)
        commandCount = command.second
    }

    val unpacked = unpackOffsets(
        workspace.bytes,
        offsetStart, offsetCount,
        offsetLowBitsStart = extraStart, offsetScale = scaling,
        lengthStart, lengthCount,
        input, source, end, "Leviathan",
    )
    return LeviathanStreams(
        literalStarts, literalSizes, commandStarts, commandSizes, commandCount,
        scratch,
        unpacked.offsets, unpacked.lengths,
    )
}

private fun runLeviathanCommands(
    output: ByteArray, start: Int, end: Int, mode: Int,
    scratch: ByteArray, streams: LeviathanStreams, history: DecodeHistory,
) {
    var destination = start
    val literalPositions = streams.literalStarts.copyOf()
    val literalEnds = IntArray(streams.literalSizes.size) { index ->
        streams.literalStarts[index] + streams.literalSizes[index]
    }
    val commandPositions = streams.commandStarts.copyOf()
    val commandEnds = IntArray(streams.commandSizes.size) { index ->
        streams.commandStarts[index] + streams.commandSizes[index]
    }
    var offsetIndex = 0
    var lengthFront = 0
    var lengthBack = streams.lengths.size
    val recent = IntArray(16)
    for (index in 8..14) recent[index] = -8
    var lastOffset = -8

    fun previous(reference: Int): Byte =
        if (reference >= 0) output[reference] else history.previous(-reference)
    fun nextLiteral(stream: Int): Int {
        val limit = if (mode == 4) streams.arenaEnd else literalEnds.getOrElse(stream) { -1 }
        if (stream !in literalPositions.indices || literalPositions[stream] >= limit) {
            throw DecompressionException("Leviathan mode $mode literal stream $stream is too short")
        }
        return scratch[literalPositions[stream]++].toInt() and 255
    }
    fun emitSubtractedLiteral(stream: Int) {
        val reference = destination + lastOffset
        if (reference >= destination) throw DecompressionException("Invalid Leviathan literal reference")
        output[destination++] = (nextLiteral(stream) + (previous(reference).toInt() and 255)).toByte()
    }
    fun literalLength(command: Int): Int {
        val inline = (command ushr 3) and 3
        if (inline != 3) return inline
        if (lengthFront >= lengthBack) throw DecompressionException("Missing Leviathan literal length")
        return streams.lengths[lengthFront++] and 0xffffff
    }

    val o1Next = if (mode == 4) IntArray(16) { nextLiteral(it) } else IntArray(0)
    var o1Context = 0
    fun copyLiterals(command: Int, finalCount: Int? = null) {
        val count = finalCount ?: when (mode) {
            0, 1 -> literalLength(command)
            else -> {
                val literalCommand = command and 0x18
                when (literalCommand) {
                    0 -> 0
                    0x08 -> 1
                    0x10 -> 2
                    else -> literalLength(command)
                }
            }
        }
        if (count > end - destination) throw DecompressionException("Leviathan literals exceed output")
        if (count == 0) return
        when (mode) {
            0 -> repeat(count) { emitSubtractedLiteral(0) }
            1 -> repeat(count) { output[destination++] = nextLiteral(0).toByte() }
            2 -> {
                emitSubtractedLiteral(1)
                repeat(count - 1) { emitSubtractedLiteral(0) }
            }
            3, 5 -> {
                val mask = if (mode == 3) 3 else 15
                repeat(count) {
                    emitSubtractedLiteral(((history.codecOutputCount + destination).toInt()) and mask)
                }
            }
            4 -> {
                o1Context = previous(destination - 1).toInt() and 255
                repeat(count) {
                    val slot = o1Context ushr 4
                    o1Context = o1Next[slot]
                    output[destination++] = o1Context.toByte()
                    o1Next[slot] = nextLiteral(slot)
                }
            }
        }
    }
    fun nextCommand(): Int {
        val stream = if (commandPositions.size == 1) 0 else
            ((history.codecOutputCount + destination).toInt()) and 7
        if (commandPositions[stream] >= commandEnds[stream]) {
            throw DecompressionException("Leviathan command stream is too short")
        }
        return scratch[commandPositions[stream]++].toInt() and 255
    }

    repeat(streams.commandCount) {
        val command = nextCommand()
        val recentIndex = command ushr 5
        var matchLength = (command and 7) + 2
        copyLiterals(command)
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
    copyLiterals(command = 0, finalCount = end - destination)
    if (mode != 4 && literalPositions.indices.any { literalPositions[it] != literalEnds[it] }) {
        throw DecompressionException("Unused Leviathan literals")
    }
    if (commandPositions.indices.any { commandPositions[it] != commandEnds[it] }) {
        throw DecompressionException("Unused Leviathan commands")
    }
}
