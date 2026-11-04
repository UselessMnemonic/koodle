package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException

/** MSB-first table metadata. Unlike speculative native readers, never reads past the payload. */
private class HeaderBits(private val source: ByteArray, private val start: Int, private val end: Int) {
    private var position = 0
    val nextByte: Int get() = start + (position + 7) / 8

    fun read(count: Int): Int {
        if (count > (end - start) * 8 - position) throw DecompressionException("Truncated Huffman table")
        var value = 0
        repeat(count) {
            value = (value shl 1) or ((source[start + position / 8].toInt() ushr (7 - position % 8)) and 1)
            position++
        }
        return value
    }
}

/** Payload bits are LSB-first within bytes; the second stream visits bytes backwards. */
private class StreamBits(
    private val source: ByteArray,
    private val start: Int,
    private val end: Int,
    private val backwards: Boolean = false,
) {
    private var position = 0
    val bytesUsed: Int get() = (position + 7) / 8

    fun read(): Int {
        if (position == (end - start) * 8) throw DecompressionException("Truncated Huffman bitstream")
        val index = if (backwards) end - 1 - position / 8 else start + position / 8
        val bit = (source[index].toInt() ushr (position % 8)) and 1
        position++
        return bit
    }
}

/** Canonical codes preserve the table's symbol ordering within each code length. */
private class HuffmanTable(symbols: IntArray, lengths: IntArray) {
    private val counts = IntArray(12)
    private val firstCode = IntArray(12)
    private val firstSymbol = IntArray(12)
    private val ordered = IntArray(symbols.size)

    init {
        var slots = 0
        for (length in lengths) {
            if (length !in 1..11) throw DecompressionException("Invalid Huffman code length")
            counts[length]++
            slots += 1 shl (11 - length)
        }
        if (slots != 2048) throw DecompressionException("Incomplete or oversubscribed Huffman table")
        var code = 0
        var index = 0
        for (length in 1..11) {
            firstCode[length] = code
            firstSymbol[length] = index
            for (i in symbols.indices) if (lengths[i] == length) ordered[index++] = symbols[i]
            code = (code + counts[length]) shl 1
        }
    }

    fun decode(bits: StreamBits): Byte {
        var code = 0
        for (length in 1..11) {
            code = (code shl 1) or bits.read()
            val offset = code - firstCode[length]
            if (offset >= 0 && offset < counts[length]) return ordered[firstSymbol[length] + offset].toByte()
        }
        throw DecompressionException("Invalid Huffman code")
    }
}

/** Sparse legacy tables for both Huffman byte-array layouts. Other table formats are deferred. */
internal fun decodeHuffman(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputEnd: Int, sixStreams: Boolean,
) {
    val bits = HeaderBits(source, start, end)
    if (bits.read(1) != 0) {
        if (bits.read(1) != 0) throw DecompressionException("Reserved Huffman table format")
        throw UnsupportedOperationException("New Huffman tables are not supported yet")
    }
    if (bits.read(1) != 0) throw UnsupportedOperationException("Dense Huffman tables are not supported yet")
    val count = bits.read(8)
    if (count == 0) throw DecompressionException("Empty Huffman alphabet")
    if (count == 1) {
        output.fill(bits.read(8).toByte(), outputStart, outputEnd)
        // Matches the reference: the declared payload is consumed, including padding.
        return
    }
    val lengthBits = bits.read(3)
    if (lengthBits > 4) throw DecompressionException("Invalid Huffman code-length width")
    val symbols = IntArray(count)
    val lengths = IntArray(count)
    val seen = BooleanArray(256)
    repeat(count) { i ->
        val symbol = bits.read(8)
        if (seen[symbol]) throw DecompressionException("Duplicate Huffman symbol")
        seen[symbol] = true
        symbols[i] = symbol
        lengths[i] = bits.read(lengthBits) + 1
    }
    val table = HuffmanTable(symbols, lengths)
    val payload = bits.nextByte
    if (!sixStreams) {
        decodeThreeStreams(source, payload, end, output, outputStart, outputEnd, table)
    } else {
        if (end - payload < 6) throw DecompressionException("Truncated six-stream Huffman header")
        val leftSize = (source[payload].toInt() and 255) or
            ((source[payload + 1].toInt() and 255) shl 8) or ((source[payload + 2].toInt() and 255) shl 16)
        val left = payload + 3
        if (leftSize > end - left) throw DecompressionException("Invalid Huffman half split")
        val middle = outputStart + (outputEnd - outputStart + 1) / 2
        decodeThreeStreams(source, left, left + leftSize, output, outputStart, middle, table)
        decodeThreeStreams(source, left + leftSize, end, output, middle, outputEnd, table)
    }
}

private fun decodeThreeStreams(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputEnd: Int, table: HuffmanTable,
) {
    if (end - start < 3) throw DecompressionException("Truncated three-stream Huffman header")
    val firstSize = (source[start].toInt() and 255) or ((source[start + 1].toInt() and 255) shl 8)
    val payload = start + 2
    if (firstSize > end - payload) throw DecompressionException("Invalid Huffman stream split")
    val middle = payload + firstSize
    val first = StreamBits(source, payload, middle)
    val second = StreamBits(source, middle, end, backwards = true)
    val third = StreamBits(source, middle, end)
    for (index in outputStart until outputEnd) {
        output[index] = table.decode(when ((index - outputStart) % 3) {
            0 -> first
            1 -> second
            else -> third
        })
        if (second.bytesUsed + third.bytesUsed > end - middle) {
            throw DecompressionException("Huffman streams overlap")
        }
    }
    if (first.bytesUsed != firstSize || second.bytesUsed + third.bytesUsed != end - middle) {
        throw DecompressionException("Unused Huffman stream bytes")
    }
}
