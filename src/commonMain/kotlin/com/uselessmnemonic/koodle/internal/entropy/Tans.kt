package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException

private class TansHeaderBits(
    private val source: ByteArray,
    private val start: Int,
    private val end: Int,
) {
    private var position = 0
    val nextByte: Int get() = start + (position + 7) / 8

    fun read(count: Int): Int {
        if (count < 0 || count > (end - start) * 8 - position) {
            throw DecompressionException("Truncated tANS table")
        }
        var value = 0
        repeat(count) {
            value = (value shl 1) or
                ((source[start + position / 8].toInt() ushr (7 - position % 8)) and 1)
            position++
        }
        return value
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

private class TansPayloadBits(
    private val source: ByteArray,
    private val start: Int,
    private val end: Int,
) {
    var forwardPosition = 0
        private set
    var backwardPosition = 0
        private set

    fun readForward(count: Int): Int = read(count, backwards = false)
    fun readBackward(count: Int): Int = read(count, backwards = true)

    private fun read(count: Int, backwards: Boolean): Int {
        if (count < 0 || forwardPosition + backwardPosition > (end - start) * 8 - count) {
            throw DecompressionException("tANS bitstreams overlap")
        }
        var value = 0
        repeat(count) { bit ->
            val position = if (backwards) backwardPosition++ else forwardPosition++
            val index = if (backwards) end - 1 - position / 8 else start + position / 8
            value = value or (((source[index].toInt() ushr (position % 8)) and 1) shl bit)
        }
        return value
    }

    fun requireConsumed() {
        val forwardBytes = (forwardPosition + 7) / 8
        val backwardBytes = (backwardPosition + 7) / 8
        if (forwardBytes + backwardBytes != end - start) {
            throw DecompressionException("Unused tANS bitstream bytes")
        }
    }
}

private data class TansEntry(val symbol: Byte, val bitCount: Int, val base: Int)
private data class WeightedSymbol(val symbol: Int, val weight: Int)

internal fun decodeTans(
    source: ByteArray, start: Int, end: Int,
    output: ByteArray, outputStart: Int, outputEnd: Int,
) {
    if (end - start < 8) throw DecompressionException("Truncated tANS payload")
    if (outputEnd - outputStart < 5) throw DecompressionException("tANS output is too small")

    val header = TansHeaderBits(source, start, end)
    if (header.read(1) != 0) throw DecompressionException("Reserved tANS header bit is set")
    val tableBits = header.read(2) + 8
    val weighted = if (header.read(1) == 0) {
        decodeLegacyTable(header, tableBits)
    } else {
        decodeNewTable(header, tableBits)
    }
    val table = buildTansTable(weighted, tableBits)
    val payloadStart = header.nextByte
    if (payloadStart >= end) throw DecompressionException("Missing tANS state payload")
    val bits = TansPayloadBits(source, payloadStart, end)
    val states = IntArray(5)
    states[0] = bits.readForward(tableBits)
    states[1] = bits.readBackward(tableBits)
    states[2] = bits.readForward(tableBits)
    states[3] = bits.readBackward(tableBits)
    states[4] = bits.readForward(tableBits)

    var destination = outputStart
    var step = 0
    val decodedEnd = outputEnd - 5
    while (destination < decodedEnd) {
        val stateIndex = if (step < 5) step else step - 5
        val state = states[stateIndex]
        if (state !in table.indices) throw DecompressionException("Invalid tANS state")
        val entry = table[state]
        output[destination++] = entry.symbol
        val nextBits = if (step < 5) {
            bits.readForward(entry.bitCount)
        } else {
            bits.readBackward(entry.bitCount)
        }
        states[stateIndex] = nextBits + entry.base
        step = (step + 1) % 10
    }
    bits.requireConsumed()
    for (state in states) {
        if (state !in 0..255) throw DecompressionException("Invalid final tANS state")
        output[destination++] = state.toByte()
    }
}

private fun decodeLegacyTable(bits: TansHeaderBits, tableBits: Int): List<WeightedSymbol> {
    val explicitCount = bits.read(3) + 1
    val deltaWidthBits = 32 - tableBits.countLeadingZeroBits()
    val deltaWidth = bits.read(deltaWidthBits)
    if (deltaWidth !in 1..tableBits) throw DecompressionException("Invalid tANS weight width")

    val seen = BooleanArray(256)
    val result = ArrayList<WeightedSymbol>(explicitCount + 1)
    var weight = 0
    var totalWeight = 0
    repeat(explicitCount) {
        val symbol = bits.read(8)
        if (seen[symbol]) throw DecompressionException("Duplicate tANS symbol")
        seen[symbol] = true
        weight += bits.read(deltaWidth)
        if (weight == 0) throw DecompressionException("Zero tANS symbol weight")
        result += WeightedSymbol(symbol, weight)
        totalWeight += weight
    }
    val finalSymbol = bits.read(8)
    if (seen[finalSymbol]) throw DecompressionException("Duplicate tANS symbol")
    val finalWeight = (1 shl tableBits) - totalWeight
    if (finalWeight <= 1 || finalWeight < weight) {
        throw DecompressionException("Invalid tANS weight sum")
    }
    result += WeightedSymbol(finalSymbol, finalWeight)
    return result.sortedBy { it.symbol }
}

private fun decodeNewTable(bits: TansHeaderBits, tableBits: Int): List<WeightedSymbol> {
    val forcedBits = bits.read(3)
    val symbolCount = bits.read(8) + 1
    if (symbolCount < 2) throw DecompressionException("Invalid tANS symbol count")
    val fluff = bits.readFluff(symbolCount)
    val rice = IntArray(symbolCount + fluff)
    for (index in rice.indices) {
        var quotient = 0
        while (bits.read(1) == 0) {
            if (++quotient > 255) throw DecompressionException("tANS Rice value is too large")
        }
        rice[index] = quotient
    }
    val symbols = decodeTansSymbolRanges(bits, symbolCount, fluff, rice)
    val result = ArrayList<WeightedSymbol>(symbolCount)
    var average = 6
    var totalWeight = 0
    repeat(symbolCount) { index ->
        val extraBits = rice[index] + forcedBits
        if (extraBits > 15) throw DecompressionException("Invalid tANS weight width")
        var value = bits.read(extraBits) + (1 shl extraBits) - (1 shl forcedBits)
        val averageQuarter = average ushr 2
        var limit = 2 * averageQuarter
        if (value <= limit) value = averageQuarter + ((value ushr 1) xor -(value and 1))
        if (limit > value) limit = value
        val weight = value + 1
        if (weight <= 0) throw DecompressionException("Invalid tANS symbol weight")
        average += limit - averageQuarter
        result += WeightedSymbol(symbols[index], weight)
        totalWeight += weight
    }
    if (totalWeight != 1 shl tableBits) throw DecompressionException("Invalid tANS weight sum")
    return result
}

private fun decodeTansSymbolRanges(
    bits: TansHeaderBits, symbolCount: Int, fluff: Int, rice: IntArray,
): IntArray {
    var extra = symbolCount
    var symbol = 0
    if (fluff and 1 != 0) {
        val width = rice[extra++]
        if (width >= 8) throw DecompressionException("Invalid tANS initial-space width")
        symbol = bits.read(width + 1) + (1 shl (width + 1)) - 1
    }
    val result = IntArray(symbolCount)
    var used = 0
    repeat(fluff ushr 1) {
        val lengthWidth = rice[extra++]
        if (lengthWidth >= 9) throw DecompressionException("Invalid tANS range-length width")
        val length = bits.read(lengthWidth) + (1 shl lengthWidth)
        val spaceWidth = rice[extra++]
        if (spaceWidth >= 8) throw DecompressionException("Invalid tANS range-space width")
        val space = bits.read(spaceWidth + 1) + (1 shl (spaceWidth + 1)) - 1
        if (length > symbolCount - used || symbol > 256 - length) {
            throw DecompressionException("Invalid tANS symbol range")
        }
        repeat(length) { result[used++] = symbol++ }
        symbol += space
    }
    val remaining = symbolCount - used
    if (remaining <= 0 || symbol > 256 - remaining) {
        throw DecompressionException("Invalid final tANS symbol range")
    }
    repeat(remaining) { result[used++] = symbol++ }
    return result
}

private fun buildTansTable(symbols: List<WeightedSymbol>, tableBits: Int): Array<TansEntry> {
    val tableSize = 1 shl tableBits
    val singletons = symbols.filter { it.weight == 1 }
    val weighted = symbols.filter { it.weight >= 2 }
    val slotsBeforeSingletons = tableSize - singletons.size
    if (slotsBeforeSingletons < 0) throw DecompressionException("Too many tANS symbols")

    val quarter = slotsBeforeSingletons ushr 2
    var next = quarter
    val pointers = IntArray(4)
    if (slotsBeforeSingletons and 3 > 0) next++
    pointers[1] = next
    next += quarter
    if (slotsBeforeSingletons and 3 > 1) next++
    pointers[2] = next
    next += quarter
    if (slotsBeforeSingletons and 3 > 2) next++
    pointers[3] = next

    val table = arrayOfNulls<TansEntry>(tableSize)
    singletons.forEachIndexed { index, symbol ->
        table[slotsBeforeSingletons + index] =
            TansEntry(symbol.symbol.toByte(), tableBits, 0)
    }
    var weightsUsed = 0
    for ((symbol, weight) in weighted) {
        if (weight > 4) {
            val symbolBits = 31 - weight.countLeadingZeroBits()
            var stateBits = tableBits - symbolBits
            var entry = TansEntry(
                symbol.toByte(), stateBits, (tableSize - 1) and (weight shl stateBits),
            )
            var baseStep = 1 shl stateBits
            var split = (1 shl (symbolBits + 1)) - weight
            repeat(4) { quarterIndex ->
                var destination = pointers[quarterIndex]
                val count = (weight + ((weightsUsed - quarterIndex - 1) and 3)) ushr 2
                if (split >= count) {
                    repeat(count) {
                        if (destination !in table.indices || table[destination] != null) invalidTable()
                        table[destination++] = entry
                        entry = entry.copy(base = entry.base + baseStep)
                    }
                    split -= count
                } else {
                    repeat(split) {
                        if (destination !in table.indices || table[destination] != null) invalidTable()
                        table[destination++] = entry
                        entry = entry.copy(base = entry.base + baseStep)
                    }
                    stateBits--
                    baseStep = baseStep ushr 1
                    entry = entry.copy(bitCount = stateBits, base = 0)
                    repeat(count - split) {
                        if (destination !in table.indices || table[destination] != null) invalidTable()
                        table[destination++] = entry
                        entry = entry.copy(base = entry.base + baseStep)
                    }
                    split = weight
                }
                pointers[quarterIndex] = destination
            }
        } else {
            var positions = ((1 shl weight) - 1) shl (weightsUsed and 3)
            positions = positions or (positions ushr 4)
            var runningWeight = weight
            repeat(weight) {
                val quarterIndex = positions.countTrailingZeroBits()
                positions = positions and (positions - 1)
                val destination = pointers[quarterIndex]++
                if (destination !in table.indices || table[destination] != null) invalidTable()
                val weightBits = 31 - runningWeight.countLeadingZeroBits()
                val stateBits = tableBits - weightBits
                table[destination] = TansEntry(
                    symbol.toByte(), stateBits,
                    (tableSize - 1) and (runningWeight shl stateBits),
                )
                runningWeight++
            }
        }
        weightsUsed += weight
    }
    if (table.any { it == null }) invalidTable()
    @Suppress("UNCHECKED_CAST")
    return table as Array<TansEntry>
}

private fun invalidTable(): Nothing = throw DecompressionException("Invalid tANS table")
