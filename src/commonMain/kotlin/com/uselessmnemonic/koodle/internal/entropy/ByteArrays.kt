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
): ByteArrayHeader {
    require(destinationStart >= 0 && destinationEnd >= destinationStart && destinationEnd <= destination.size)
    require(source !== destination)
    val header = readByteArrayHeader(source, start, end, destinationEnd - destinationStart)
    val payload = start + header.headerSize
    val payloadEnd = payload + header.encodedSize
    when (header.encoding) {
        ByteEncoding.RAW -> source.copyInto(destination, destinationStart, payload, payloadEnd)
        ByteEncoding.HUFFMAN, ByteEncoding.HUFFMAN6 -> decodeHuffman(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
            sixStreams = header.encoding == ByteEncoding.HUFFMAN6,
        )
        ByteEncoding.RLE -> decodeRle(
            source, payload, payloadEnd, destination, destinationStart, destinationStart + header.decodedSize,
            workspace,
            if (workspace.owns(destination)) maxOf(workspaceStart, destinationStart + header.decodedSize) else workspaceStart,
        )
        else -> throw UnsupportedOperationException("Byte-array encoding ${header.encoding} is not supported yet")
    }
    return header
}

private fun decodeRle(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outStart: Int, outEnd: Int,
    workspace: EntropyWorkspace, workspaceStart: Int,
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
                workspace, workspaceStart + nested.decodedSize,
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
