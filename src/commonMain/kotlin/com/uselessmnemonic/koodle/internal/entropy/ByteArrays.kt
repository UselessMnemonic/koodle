package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException

internal enum class ByteEncoding { RAW, TANS, HUFFMAN, RLE, HUFFMAN6, RECURSIVE }

internal data class ByteArrayHeader(
    val encoding: ByteEncoding,
    val headerSize: Int,
    val encodedSize: Int,
    val decodedSize: Int,
)

/** Lazily allocated bounded scratch arena shared by nested entropy decoders. */
internal class EntropyWorkspace(private val capacity: Int = 0x40000) {
    private var storage: ByteArray? = null

    val bytes: ByteArray
        get() = storage ?: ByteArray(capacity).also { storage = it }

    fun owns(array: ByteArray): Boolean = storage === array

    fun requireRange(start: Int, size: Int) {
        if (start < 0 || size < 0 || start > capacity - size) {
            throw DecompressionException("Nested byte arrays exceed entropy workspace")
        }
    }
}

/** Parses one bounded array, validating its entire payload and output capacity. */
internal fun readByteArrayHeader(
    source: ByteArray, start: Int, end: Int, outputCapacity: Int,
): ByteArrayHeader {
    require(start >= 0 && end >= start && end <= source.size)
    require(outputCapacity >= 0)
    fun need(count: Int) {
        if (end - start < count) throw DecompressionException("Truncated byte-array header")
    }
    fun be(offset: Int, count: Int): Long {
        var value = 0L
        repeat(count) { value = (value shl 8) or (source[start + offset + it].toLong() and 255) }
        return value
    }
    need(2)
    val first = source[start].toInt() and 255
    val kind = (first ushr 4) and 7
    val encoding = ByteEncoding.entries.getOrNull(kind)
        ?: throw DecompressionException("Invalid byte-array encoding: $kind")
    val headerSize: Int
    val encodedSize: Int
    val decodedSize: Int
    if (encoding == ByteEncoding.RAW) {
        headerSize = if (first >= 128) 2 else 3
        need(headerSize)
        val bits = be(0, headerSize).toInt()
        if (headerSize == 3 && bits and 0x3ffff.inv() != 0) {
            throw DecompressionException("Reserved raw-array header bits are set")
        }
        encodedSize = if (headerSize == 2) bits and 0xfff else bits
        decodedSize = encodedSize
    } else if (first >= 128) {
        headerSize = 3
        need(headerSize)
        val bits = be(0, 3).toInt()
        encodedSize = bits and 0x3ff
        decodedSize = encodedSize + ((bits ushr 10) and 0x3ff) + 1
    } else {
        headerSize = 5
        need(headerSize)
        val bits = be(1, 4)
        encodedSize = (bits and 0x3ffff).toInt()
        decodedSize = (((bits ushr 18) or (first.toLong() shl 14)) and 0x3ffff).toInt() + 1
        if (encodedSize >= decodedSize) throw DecompressionException("Byte array does not reduce its size")
    }
    if (encodedSize > end - start - headerSize) throw DecompressionException("Truncated byte-array payload")
    if (decodedSize > outputCapacity) throw DecompressionException("Byte array exceeds output capacity")
    return ByteArrayHeader(encoding, headerSize, encodedSize, decodedSize)
}

/** Decodes one array; trailing input belongs to the next array. No input arrays are retained. */
internal fun decodeByteArray(
    source: ByteArray, start: Int, end: Int,
    destination: ByteArray, destinationStart: Int, destinationEnd: Int,
    workspace: EntropyWorkspace = EntropyWorkspace(), workspaceStart: Int = 0,
    depth: Int = 0,
): ByteArrayHeader {
    require(destinationStart >= 0 && destinationEnd >= destinationStart && destinationEnd <= destination.size)
    require(source !== destination)
    if (depth > 64) throw DecompressionException("Byte-array nesting is too deep")
    val header = readByteArrayHeader(source, start, end, destinationEnd - destinationStart)
    val payload = start + header.headerSize
    val payloadEnd = payload + header.encodedSize
    val nestedWorkspaceStart =
        if (workspace.owns(destination)) maxOf(workspaceStart, destinationStart + header.decodedSize) else workspaceStart
    when (header.encoding) {
        ByteEncoding.RAW -> source.copyInto(destination, destinationStart, payload, payloadEnd)
        ByteEncoding.TANS -> decodeTans(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
        )
        ByteEncoding.HUFFMAN, ByteEncoding.HUFFMAN6 -> decodeHuffman(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
            sixStreams = header.encoding == ByteEncoding.HUFFMAN6,
        )
        ByteEncoding.RLE -> decodeRle(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
            workspace, nestedWorkspaceStart, depth,
        )
        ByteEncoding.RECURSIVE -> decodeRecursive(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
            workspace, nestedWorkspaceStart, depth,
        )
    }
    return header
}

private fun decodeRecursive(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputEnd: Int,
    workspace: EntropyWorkspace, workspaceStart: Int, depth: Int,
) {
    if (end - start < 6) throw DecompressionException("Truncated recursive byte array")
    val control = source[start].toInt() and 255
    if (control and 0x80 != 0) {
        decodeInterleaved(
            source, start, end, output, outputStart, outputEnd,
            workspace, workspaceStart, depth,
        )
        return
    }
    val count = control and 0x7f
    if (count > 2) throw DecompressionException("Too many sequential byte arrays")
    var input = start + 1
    var written = outputStart
    repeat(count) {
        val child = readByteArrayHeader(source, input, end, outputEnd - written)
        val consumed = child.headerSize + child.encodedSize
        decodeByteArray(
            source, input, input + consumed,
            output, written, written + child.decodedSize,
            workspace, workspaceStart, depth + 1,
        )
        input += consumed
        written += child.decodedSize
    }
    if (input != end) throw DecompressionException("Unused recursive byte-array input")
    if (written != outputEnd) throw DecompressionException("Recursive byte-array output size mismatch")
}

private fun decodeInterleaved(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputEnd: Int,
    workspace: EntropyWorkspace, workspaceStart: Int, depth: Int,
) {
    val fileCount = source[start].toInt() and 0x3f
    var input = start + 1
    if (fileCount == 0) {
        val child = readByteArrayHeader(source, input, end, outputEnd - outputStart)
        val consumed = child.headerSize + child.encodedSize
        decodeByteArray(
            source, input, input + consumed,
            output, outputStart, outputStart + child.decodedSize,
            workspace, workspaceStart, depth + 1,
        )
        if (input + consumed != end || child.decodedSize != outputEnd - outputStart) {
            throw DecompressionException("Invalid direct multi-array payload")
        }
        return
    }

    val arrayPositions = IntArray(fileCount)
    val arrayRemaining = IntArray(fileCount)
    var scratch = workspaceStart
    var totalSize = 0
    repeat(fileCount) { index ->
        val child = readByteArrayHeader(source, input, end, 0x40000 - totalSize)
        val consumed = child.headerSize + child.encodedSize
        workspace.requireRange(scratch, child.decodedSize)
        decodeByteArray(
            source, input, input + consumed,
            workspace.bytes, scratch, scratch + child.decodedSize,
            workspace, scratch + child.decodedSize, depth + 1,
        )
        arrayPositions[index] = scratch
        arrayRemaining[index] = child.decodedSize
        scratch += child.decodedSize
        totalSize += child.decodedSize
        input += consumed
    }
    if (end - input < 2) throw DecompressionException("Truncated multi-array control")
    val control = (source[input].toInt() and 255) or ((source[input + 1].toInt() and 255) shl 8)
    input += 2

    val indexHeader = readByteArrayHeader(source, input, end, totalSize)
    val indexCount = indexHeader.decodedSize
    if (indexCount < 1) throw DecompressionException("Empty multi-array index stream")
    val combined = control and 0x8000 != 0
    val lengthCount = if (combined) indexCount else indexCount - 1
    val lengthStart = scratch
    val indexStart = lengthStart + indexCount
    val buffersEnd = indexStart + indexCount
    workspace.requireRange(lengthStart, indexCount * 2)

    val indexConsumed = indexHeader.headerSize + indexHeader.encodedSize
    decodeByteArray(
        source, input, input + indexConsumed,
        workspace.bytes, indexStart, indexStart + indexCount,
        workspace, buffersEnd, depth + 1,
    )
    input += indexConsumed
    if (combined) {
        repeat(indexCount) { index ->
            val value = workspace.bytes[indexStart + index].toInt() and 255
            workspace.bytes[lengthStart + index] = (value ushr 4).toByte()
            workspace.bytes[indexStart + index] = (value and 15).toByte()
        }
    } else {
        val lengthHeader = readByteArrayHeader(source, input, end, lengthCount)
        if (lengthHeader.decodedSize != lengthCount) {
            throw DecompressionException("Multi-array length stream has wrong size")
        }
        val lengthConsumed = lengthHeader.headerSize + lengthHeader.encodedSize
        decodeByteArray(
            source, input, input + lengthConsumed,
            workspace.bytes, lengthStart, lengthStart + lengthCount,
            workspace, buffersEnd, depth + 1,
        )
        input += lengthConsumed
        repeat(lengthCount) { index ->
            if ((workspace.bytes[lengthStart + index].toInt() and 255) > 16) {
                throw DecompressionException("Invalid multi-array length width")
            }
        }
    }

    val bitBytes = control and 0x3fff
    if (bitBytes > end - input || input + bitBytes != end) {
        throw DecompressionException("Invalid multi-array bitstream size")
    }
    val bitEnd = input + bitBytes
    var forwardBits = 0
    var backwardBits = 0
    fun readBits(count: Int, backwards: Boolean): Int {
        if (count == 0) return 0
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
        val forwardWidth = workspace.bytes[lengthStart + length].toInt() and 255
        val backwardWidth = workspace.bytes[lengthStart + length + 1].toInt() and 255
        lengths[length++] = (1 shl forwardWidth) or readBits(forwardWidth, backwards = false)
        lengths[length++] = (1 shl backwardWidth) or readBits(backwardWidth, backwards = true)
    }
    if (length < lengthCount) {
        val width = workspace.bytes[lengthStart + length].toInt() and 255
        lengths[length] = (1 shl width) or readBits(width, backwards = false)
    }

    if (workspace.bytes[indexStart + indexCount - 1] != 0.toByte()) {
        throw DecompressionException("Multi-array index stream is not terminated")
    }
    var indexPosition = 0
    var lengthPosition = 0
    var written = outputStart
    while (true) {
        if (indexPosition >= indexCount) throw DecompressionException("Truncated multi-array indexes")
        val sourceIndex = workspace.bytes[indexStart + indexPosition++].toInt() and 255
        if (sourceIndex == 0) break
        if (sourceIndex !in 1..fileCount || lengthPosition >= lengthCount) {
            throw DecompressionException("Invalid multi-array source index")
        }
        val count = lengths[lengthPosition++]
        val array = sourceIndex - 1
        if (count > arrayRemaining[array] || count > outputEnd - written) {
            throw DecompressionException("Multi-array interval exceeds its source")
        }
        workspace.bytes.copyInto(
            output, written, arrayPositions[array], arrayPositions[array] + count,
        )
        arrayPositions[array] += count
        arrayRemaining[array] -= count
        written += count
    }
    if (combined) lengthPosition++ // The terminator carries an unused length nibble.
    if (written != outputEnd || indexPosition != indexCount || lengthPosition != lengthCount ||
        arrayRemaining.any { it != 0 }
    ) {
        throw DecompressionException("Multi-array streams were not consumed exactly")
    }
}

private fun decodeRle(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outStart: Int, outEnd: Int,
    workspace: EntropyWorkspace, workspaceStart: Int, depth: Int,
) {
    if (start == end) throw DecompressionException("Empty RLE payload")
    if (end - start == 1) {
        output.fill(source[start], outStart, outEnd)
        return
    }
    val commandSource: ByteArray
    val commandsStart: Int
    val commandsEnd: Int
    if (source[start] == 0.toByte()) {
        commandSource = source
        commandsStart = start + 1
        commandsEnd = end
    } else {
        val nested = readByteArrayHeader(source, start, end, 0x40000)
        if (nested.encoding == ByteEncoding.RAW) {
            commandSource = source
            commandsStart = start + nested.headerSize
            commandsEnd = end
        } else {
            val consumed = nested.headerSize + nested.encodedSize
            val trailing = end - start - consumed
            val commandSize = nested.decodedSize + trailing
            workspace.requireRange(workspaceStart, commandSize)
            decodeByteArray(
                source, start, start + consumed,
                workspace.bytes, workspaceStart, workspaceStart + nested.decodedSize,
                workspace, workspaceStart + nested.decodedSize, depth + 1,
            )
            source.copyInto(
                workspace.bytes, workspaceStart + nested.decodedSize,
                start + consumed, end,
            )
            commandSource = workspace.bytes
            commandsStart = workspaceStart
            commandsEnd = workspaceStart + commandSize
        }
    }
    var front = commandsStart
    var back = commandsEnd
    var written = outStart
    var fill: Byte = 0
    fun copyAndFill(literals: Int, repeats: Int) {
        if (literals > back - front) throw DecompressionException("RLE literals cross command data")
        if (literals > outEnd - written || repeats > outEnd - written - literals) {
            throw DecompressionException("RLE command exceeds output")
        }
        commandSource.copyInto(output, written, front, front + literals)
        front += literals
        written += literals
        output.fill(fill, written, written + repeats)
        written += repeats
    }
    while (front < back) {
        val command = commandSource[back - 1].toInt() and 255
        when {
            command == 0 || command > 0x2f -> {
                back--
                copyAndFill(command.inv() and 15, command ushr 4)
            }
            command == 1 -> {
                back--
                if (front == back) throw DecompressionException("Missing RLE fill value")
                fill = commandSource[front++]
            }
            else -> {
                if (back - front < 2) throw DecompressionException("Truncated RLE command")
                back -= 2
                val word = (commandSource[back].toInt() and 255) or (command shl 8)
                when {
                    command >= 0x10 -> {
                        val data = word - 4096
                        copyAndFill(data and 63, data ushr 6)
                    }
                    command >= 9 -> copyAndFill(0, (word - 0x8ff) * 128)
                    else -> copyAndFill((word - 511) * 64, 0)
                }
            }
        }
    }
    if (written != outEnd) throw DecompressionException("RLE output size mismatch")
}
