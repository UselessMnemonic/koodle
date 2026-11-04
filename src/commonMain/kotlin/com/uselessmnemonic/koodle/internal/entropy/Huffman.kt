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

    fun readRunLength(): Int {
        var zeros = 0
        while (read(1) == 0) {
            if (++zeros > 7) throw DecompressionException("Huffman symbol run is too large")
        }
        val width = zeros + 1
        return ((1 shl width) or read(width)) - 1
    }

    fun readLengthDelta(forcedBits: Int): Int {
        var zeros = 0
        while (read(1) == 0) {
            if (++zeros > (20 ushr forcedBits)) {
                throw DecompressionException("Huffman length delta is too large")
            }
        }
        val value = (zeros shl forcedBits) or read(forcedBits)
        return if (value and 1 == 0) value ushr 1 else -(value ushr 1) - 1
    }

    fun readFluff(symbolCount: Int): Int {
        if (symbolCount == 256) return 0
        val choices = 2 * minOf(257 - symbolCount, symbolCount)
        val width = 32 - (choices - 1).countLeadingZeroBits()
        val cutoff = (1 shl width) - choices
        val prefix = read(width - 1)
        return if (prefix < cutoff) prefix else ((prefix shl 1) or read(1)) - cutoff
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
    val newFormat = bits.read(1) != 0
    if (newFormat && bits.read(1) != 0) throw DecompressionException("Reserved Huffman table format")
    val symbols: IntArray
    val lengths: IntArray
    if (newFormat) {
        val forcedBits = bits.read(2)
        val count = bits.read(8) + 1
        val fluff = bits.readFluff(count)
        val rice = IntArray(count + fluff)
        for (index in rice.indices) {
            var quotient = 0
            while (bits.read(1) == 0) {
                if (++quotient > 255) throw DecompressionException("Golomb-Rice value is too large")
            }
            rice[index] = quotient
        }
        if (forcedBits > 0) {
            for (index in 0 until count) rice[index] = (rice[index] shl forcedBits) or bits.read(forcedBits)
        }
        lengths = IntArray(count)
        var runningSum = 30
        repeat(count) { index ->
            val value = rice[index]
            val delta = if (value and 1 == 0) value ushr 1 else -(value ushr 1) - 1
            val length = delta + (runningSum ushr 2) + 1
            if (length !in 1..11) throw DecompressionException("Invalid Huffman code length")
            lengths[index] = length
            runningSum += delta
        }
        symbols = decodeSymbolRanges(bits, count, fluff, rice)
    } else if (bits.read(1) != 0) {
        val forcedBits = bits.read(2)
        var symbol = 0
        var averageTimesFour = 32
        val symbolList = mutableListOf<Int>()
        val lengthList = mutableListOf<Int>()
        var skipZeros = bits.read(1) != 0
        while (symbol < 256) {
            if (skipZeros) {
                skipZeros = false
            } else {
                symbol += bits.readRunLength()
                if (symbol >= 256) break
            }
            var run = bits.readRunLength()
            if (run <= 0 || run > 256 - symbol) {
                throw DecompressionException("Invalid Huffman symbol run")
            }
            repeat(run) {
                val length = ((averageTimesFour + 2) ushr 2) + bits.readLengthDelta(forcedBits)
                if (length !in 1..11) throw DecompressionException("Invalid Huffman code length")
                symbolList += symbol++
                lengthList += length
                averageTimesFour = length + ((3 * averageTimesFour + 2) ushr 2)
            }
        }
        if (symbol != 256 || symbolList.size < 2) {
            throw DecompressionException("Invalid dense Huffman alphabet")
        }
        symbols = symbolList.toIntArray()
        lengths = lengthList.toIntArray()
    } else {
        val count = bits.read(8)
        if (count == 0) throw DecompressionException("Empty Huffman alphabet")
        if (count == 1) {
            output.fill(bits.read(8).toByte(), outputStart, outputEnd)
            // Matches the reference: the declared payload is consumed, including padding.
            return
        }
        val lengthBits = bits.read(3)
        if (lengthBits > 4) throw DecompressionException("Invalid Huffman code-length width")
        symbols = IntArray(count)
        lengths = IntArray(count)
        val seen = BooleanArray(256)
        repeat(count) { i ->
            val symbol = bits.read(8)
            if (seen[symbol]) throw DecompressionException("Duplicate Huffman symbol")
            seen[symbol] = true
            symbols[i] = symbol
            lengths[i] = bits.read(lengthBits) + 1
        }
    }
    if (symbols.size == 1) {
        output.fill(symbols[0].toByte(), outputStart, outputEnd)
        return
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

private fun decodeSymbolRanges(bits: HeaderBits, count: Int, fluff: Int, rice: IntArray): IntArray {
    var extra = count
    var symbol = 0
    if (fluff and 1 != 0) {
        val width = rice[extra++]
        if (width >= 8) throw DecompressionException("Invalid Huffman initial-space width")
        symbol = bits.read(width + 1) + (1 shl (width + 1)) - 1
    }
    var used = 0
    val result = IntArray(count)
    repeat(fluff ushr 1) {
        val lengthWidth = rice[extra++]
        if (lengthWidth >= 9) throw DecompressionException("Invalid Huffman range-length width")
        val length = bits.read(lengthWidth) + (1 shl lengthWidth)
        val spaceWidth = rice[extra++]
        if (spaceWidth >= 8) throw DecompressionException("Invalid Huffman range-space width")
        val space = bits.read(spaceWidth + 1) + (1 shl (spaceWidth + 1)) - 1
        if (length > count - used || symbol > 256 - length) {
            throw DecompressionException("Invalid Huffman symbol range")
        }
        repeat(length) { result[used++] = symbol++ }
        symbol += space
    }
    val remaining = count - used
    if (remaining <= 0 || symbol > 256 - remaining) {
        throw DecompressionException("Invalid final Huffman symbol range")
    }
    repeat(remaining) { result[used++] = symbol++ }
    return result
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
