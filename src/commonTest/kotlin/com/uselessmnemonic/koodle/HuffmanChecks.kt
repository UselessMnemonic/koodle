package com.uselessmnemonic.koodle

import com.uselessmnemonic.koodle.internal.entropy.decodeByteArray

private inline fun <reified T : Throwable> rejectsHuffman(block: () -> Unit) {
    try { block() } catch (error: Throwable) {
        check(error is T) { "Expected ${T::class}, got $error" }
        return
    }
    error("Expected ${T::class}")
}

internal fun checkHuffman() {
    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }
    fun binary(value: Int, width: Int): String = value.toString(2).padStart(width, '0')
    fun pack(bits: String, lsb: Boolean = false): ByteArray {
        val result = ByteArray((bits.length + 7) / 8)
        for (i in bits.indices) if (bits[i] == '1') {
            val bit = if (lsb) i % 8 else 7 - i % 8
            result[i / 8] = (result[i / 8].toInt() or (1 shl bit)).toByte()
        }
        return result
    }
    fun array(payload: ByteArray, size: Int, six: Boolean = false): ByteArray {
        val n = size - 1
        val bits = ((n.toLong() and 0x3fff) shl 18) or payload.size.toLong()
        return bytes(((if (six) 4 else 2) shl 4) or (n ushr 14)) +
            ByteArray(4) { (bits ushr (24 - it * 8)).toByte() } + payload
    }
    fun decode(payload: ByteArray, size: Int, six: Boolean = false): ByteArray {
        val input = array(payload, size, six)
        val output = ByteArray(size + 2) { 77 }
        decodeByteArray(input, 0, input.size, output, 1, size + 1)
        check(output.first() == 77.toByte() && output.last() == 77.toByte())
        return output.copyOfRange(1, size + 1)
    }
    fun table(symbols: List<Int>, codes: List<String>, width: Int = 4): ByteArray {
        var bits = "00" + binary(symbols.size, 8)
        if (symbols.size == 1) bits += binary(symbols.single(), 8)
        else {
            bits += binary(width, 3)
            for (i in symbols.indices) {
                bits += binary(symbols[i], 8)
                if (width > 0) bits += binary(codes[i].length - 1, width)
            }
        }
        return pack(bits)
    }
    fun gamma(value: Int): String {
        val binary = binary(value + 1, 32).trimStart('0')
        return "0".repeat(binary.length - 2) + binary
    }
    fun denseTable(lengths: Map<Int, Int>, forcedBits: Int = 0): ByteArray {
        require(lengths.size >= 2 && forcedBits in 0..3)
        var bits = "01" + binary(forcedBits, 2)
        var symbol = 0
        var averageTimesFour = 32
        val first = lengths.keys.min()
        bits += if (first == 0) "1" else "0" + gamma(first)
        while (symbol < 256) {
            if (symbol < first) symbol = first
            if (!lengths.containsKey(symbol)) {
                var next = symbol
                while (next < 256 && !lengths.containsKey(next)) next++
                bits += gamma(next - symbol)
                symbol = next
                if (symbol == 256) break
            }
            var end = symbol
            while (end < 256 && lengths.containsKey(end)) end++
            bits += gamma(end - symbol)
            while (symbol < end) {
                val target = lengths.getValue(symbol++)
                val delta = target - ((averageTimesFour + 2) ushr 2)
                val zigzag = if (delta >= 0) delta * 2 else -delta * 2 - 1
                val quotient = zigzag ushr forcedBits
                bits += "0".repeat(quotient) + "1"
                if (forcedBits > 0) bits += binary(zigzag and ((1 shl forcedBits) - 1), forcedBits)
                averageTimesFour = target + ((3 * averageTimesFour + 2) ushr 2)
            }
        }
        return pack(bits)
    }
    fun streams(values: List<Int>, codes: Map<Int, String>): ByteArray {
        val parts = (0..2).map { stream ->
            pack(values.filterIndexed { i, _ -> i % 3 == stream }.joinToString("") { codes.getValue(it) }, lsb = true)
        }
        // Wire order: first forwards, third forwards, second backwards.
        return bytes(parts[0].size and 255, parts[0].size ushr 8) + parts[0] + parts[2] + parts[1].reversedArray()
    }
    fun payload(values: List<Int>, symbols: List<Int>, codes: List<String>, six: Boolean, width: Int = 4): ByteArray {
        val mapping = symbols.zip(codes).toMap()
        val data = if (!six) streams(values, mapping) else {
            val half = (values.size + 1) / 2
            val left = streams(values.take(half), mapping)
            bytes(left.size and 255, (left.size ushr 8) and 255, left.size ushr 16) + left + streams(values.drop(half), mapping)
        }
        return table(symbols, codes, width) + data
    }
    for (six in listOf(false, true)) {
        check(decode(table(listOf(0xab), listOf("")), 100, six).contentEquals(ByteArray(100) { 0xab.toByte() }))
        val symbols = listOf(200, 3, 77)
        val codes = listOf("0", "10", "11")
        for (size in listOf(99, 100, 101)) {
            val values = List(size) { symbols[(it * 7 + it / 5) % 3] }
            val encoded = payload(values, symbols, codes, six)
            check(decode(encoded, size, six).contentEquals(values.map { it.toByte() }.toByteArray()))
            rejectsHuffman<DecompressionException> { decode(encoded.copyOf(encoded.size / 2), size, six) }
            rejectsHuffman<DecompressionException> { decode(encoded + bytes(0), size, six) }
        }
        val symbols11 = (0..11).map { 240 - it * 7 }
        val codes11 = (0..10).map { "1".repeat(it) + "0" } + "1".repeat(11)
        val values11 = List(513) { symbols11[it % 12] }
        check(decode(payload(values11, symbols11, codes11, six), 513, six)
            .contentEquals(values11.map { it.toByte() }.toByteArray()))
        val two = List(100) { it % 2 }
        check(decode(payload(two, listOf(0, 1), listOf("0", "1"), six, width = 0), 100, six)
            .contentEquals(two.map { it.toByte() }.toByteArray()))
        for ((lengthMap, codes) in listOf(
            mapOf(0 to 1, 1 to 1) to listOf("0", "1"),
            mapOf(2 to 1, 100 to 2, 200 to 2) to listOf("0", "10", "11"),
        )) {
            val denseSymbols = lengthMap.keys.toList()
            val denseValues = List(257) { denseSymbols[(it * 5 + it / 9) % denseSymbols.size] }
            val mapping = denseSymbols.zip(codes).toMap()
            val data = if (!six) streams(denseValues, mapping) else {
                val half = (denseValues.size + 1) / 2
                val left = streams(denseValues.take(half), mapping)
                bytes(left.size and 255, (left.size ushr 8) and 255, left.size ushr 16) +
                    left + streams(denseValues.drop(half), mapping)
            }
            for (forced in 0..3) {
                check(decode(denseTable(lengthMap, forced) + data, denseValues.size, six)
                    .contentEquals(denseValues.map { it.toByte() }.toByteArray()))
            }
        }
    }
    rejectsHuffman<DecompressionException> { decode(pack("0000000000"), 100) } // empty alphabet
    rejectsHuffman<DecompressionException> { decode(bytes(0xc0, 0), 100) } // reserved format
    rejectsHuffman<UnsupportedOperationException> { decode(bytes(0x80, 0), 100) } // new table
    rejectsHuffman<DecompressionException> { decode(bytes(0x40, 0), 100) } // truncated dense table
    rejectsHuffman<DecompressionException> { decode(table(listOf(7, 7), listOf("0", "1")), 100) }
    rejectsHuffman<DecompressionException> { decode(table(listOf(1, 2), listOf("00", "01")), 100) }
    rejectsHuffman<DecompressionException> { decode(table(listOf(1, 2, 3), listOf("0", "1", "0")), 100) }
    rejectsHuffman<DecompressionException> { decode(table(listOf(1, 2), listOf("0".repeat(12), "1")), 100) }
    rejectsHuffman<DecompressionException> { decode(pack("00" + binary(2, 8) + "101"), 100) }
    rejectsHuffman<DecompressionException> { decode(pack("0100" + gamma(257)), 100) }
    rejectsHuffman<DecompressionException> { decode(pack("0101" + gamma(257)), 100) }
    rejectsHuffman<DecompressionException> {
        decode(denseTable(mapOf(0 to 12, 1 to 1)) + bytes(0, 0, 0), 100)
    }
    rejectsHuffman<DecompressionException> {
        decode(denseTable(mapOf(0 to 2, 1 to 2)) + bytes(0, 0, 0), 100)
    }
    rejectsHuffman<DecompressionException> {
        decode(pack("0101" + gamma(2) + "0".repeat(22) + "1"), 100)
    }
    val basicTable = table(listOf(65, 66), listOf("0", "1"), width = 0)
    rejectsHuffman<DecompressionException> { decode(basicTable + bytes(255, 255, 0), 100) }
    rejectsHuffman<DecompressionException> { decode(basicTable + bytes(255, 255, 255, 0, 0, 0), 100, true) }
    // Three streams cannot reuse the same byte in the shared middle region.
    rejectsHuffman<DecompressionException> { decode(basicTable + bytes(1, 0, 0, 0), 100) }
    val values = List(101) { if (it % 7 == 0) 66 else 65 }
    val entropy = array(payload(values, listOf(65, 66), listOf("0", "1"), false), values.size)
    val size = entropy.size - 1
    val framed = bytes(0x8c, 6, size ushr 16, (size ushr 8) and 255, size and 255) + entropy
    for (inputChunk in listOf(1, 7, framed.size)) {
        val decoder = OozDecoder(values.size.toLong())
        val actual = mutableListOf<Byte>()
        var consumed = 0
        while (true) {
            val end = minOf(framed.size, consumed + inputChunk)
            val out = ByteArray(3)
            val result = decoder.decode(framed, out, consumed, end, endOfInput = end == framed.size)
            consumed += result.bytesConsumed
            repeat(result.bytesWritten) { actual += out[it] }
            if (result.status == DecodeStatus.FINISHED) break
            check(result.bytesConsumed > 0 || result.bytesWritten > 0)
        }
        check(consumed == framed.size && actual == values.map { it.toByte() })
    }
}
