package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory

/** Adaptive cumulative-frequency model shared by Bitknit's symbol alphabets. */
internal class BitknitModel(
    private val symbolCount: Int,
    boundaryCount: Int,
    lookupSize: Int,
) {
    private val shift = if (boundaryCount == 301) 6 else 9
    private val frequencyIncrement = 1026 - boundaryCount
    private val boundaries = IntArray(boundaryCount) { index ->
        if (shift == 6) {
            if (index < 264) (0x8000 - 300 + 264) * index / 264
            else 0x8000 - 300 + index
        } else {
            0x8000 * index / symbolCount
        }
    }
    private val frequencies = IntArray(symbolCount) { 1 }
    private var adaptationRemaining = 1024
    private val lookup = IntArray(lookupSize)

    init {
        fillLookup()
    }

    /** High 32 bits are the updated coder state; low 32 bits are the symbol. */
    fun decode(bits: UInt): Long {
        val masked = (bits and 0x7fffu).toInt()
        val lookupIndex = masked ushr shift
        if (lookupIndex !in lookup.indices) throw DecompressionException("Invalid Bitknit model state")
        var symbol = lookup[lookupIndex]
        if (masked > boundaries.getOrElse(symbol + 1) { -1 }) symbol++
        while (symbol + 1 < boundaries.size && boundaries[symbol + 1] <= masked) symbol++
        if (symbol !in frequencies.indices || symbol + 1 !in boundaries.indices) {
            throw DecompressionException("Invalid Bitknit symbol")
        }
        val start = boundaries[symbol].toUInt()
        val end = boundaries[symbol + 1].toUInt()
        val nextBits = masked.toUInt() + (bits shr 15) * (end - start) - start
        frequencies[symbol] = (frequencies[symbol] + 31) and 0xffff
        adaptationRemaining--
        if (adaptationRemaining == 0) adapt(symbol)
        return (nextBits.toLong() shl 32) or symbol.toLong()
    }

    private fun adapt(symbol: Int) {
        adaptationRemaining = 1024
        frequencies[symbol] = (frequencies[symbol] + frequencyIncrement) and 0xffff
        var sum = 0u
        for (index in frequencies.indices) {
            sum += frequencies[index].toUInt()
            val boundary = boundaries[index + 1].toUInt()
            boundaries[index + 1] = (boundary + ((sum - boundary) shr 1)).toInt() and 0xffff
        }
        frequencies.fill(1)
        fillLookup()
    }

    private fun fillLookup() {
        var position = 0
        for (index in 1 until boundaries.size) {
            val end = ((boundaries[index] - 1) ushr shift) + 1
            if (end !in position..lookup.size) {
                throw DecompressionException("Invalid Bitknit lookup table")
            }
            lookup.fill(index - 1, position, end)
            position = end
        }
    }
}

/** Adaptive state retained across Bitknit quanta and replaced at codec restarts. */
internal class BitknitState {
    val recentDistances: IntArray = IntArray(8) { 1 }
    var lastMatchDistance: Int = 1
    var recentDistanceMask: UInt = (1..7).fold(0u) { mask, index ->
        mask or (index.toUInt() shl (index * 3))
    }
    val literals: Array<BitknitModel> = Array(4) { BitknitModel(300, 301, 512) }
    val distanceLowBits: Array<BitknitModel> = Array(4) { BitknitModel(40, 41, 64) }
    val distanceBitCounts: BitknitModel = BitknitModel(21, 22, 64)
}

internal fun decodeBitknitQuantum(
    input: ByteArray,
    inputSize: Int,
    output: ByteArray,
    outputSize: Int,
    state: BitknitState,
    history: DecodeHistory,
) {
    require(inputSize in 0..input.size)
    require(outputSize in 0..output.size)
    if (outputSize < 4) throw DecompressionException("Bitknit quantum is too short")
    BitknitDecoder(input, inputSize, output, outputSize, state, history).decode()
}

private class BitknitDecoder(
    private val input: ByteArray,
    private val inputSize: Int,
    private val output: ByteArray,
    private val outputSize: Int,
    private val state: BitknitState,
    private val history: DecodeHistory,
) {
    private var inputPosition = 0
    private var outputPosition = 0
    private val outputBase = history.outputCount
    private var bits = 0x10000u
    private var bits2 = 0x10000u

    fun decode() {
        var recentMask = state.recentDistanceMask
        val initial = readUInt()
        if (initial < 0x10000u) throw DecompressionException("Invalid Bitknit initial state")

        var accumulator = initial shr 4
        val initialBitCount = (initial and 15u).toInt()
        if (accumulator < 0x10000u) accumulator = (accumulator shl 16) or readUShort()
        bits = accumulator shr initialBitCount
        if (bits < 0x10000u) bits = (bits shl 16) or readUShort()
        accumulator = (accumulator shl 16) or readUShort()
        val secondWidth = initialBitCount + 16
        bits2 = (1u shl secondWidth) or (accumulator and ((1u shl secondWidth) - 1u))

        if (outputBase == 0L) {
            write((bits and 255u).toInt())
            bits = bits shr 8
            renormalize()
        }

        val decodedEnd = outputSize - 4
        while (outputPosition < decodedEnd) {
            var symbol = lookupLiteral()
            renormalize()

            if (symbol < 256) {
                writeLiteral(symbol)
                if (outputPosition >= decodedEnd) break
                symbol = lookupLiteral()
                renormalize()
                if (symbol < 256) {
                    writeLiteral(symbol)
                    continue
                }
            }

            if (symbol >= 288) {
                val extraBitCount = symbol - 287
                symbol = (bits and ((1u shl extraBitCount) - 1u)).toInt() +
                    (1 shl extraBitCount) + 286
                bits = bits shr extraBitCount
                renormalize()
            }
            val copyLength = symbol - 254
            if (copyLength < 2) throw DecompressionException("Invalid Bitknit match length")

            val lowSymbol = lookupDistanceLowBits()
            renormalize()
            val matchDistance: Int
            if (lowSymbol >= 8) {
                val bitCount = lookupDistanceBitCount()
                renormalize()
                val inlineBitCount = bitCount and 15
                var distanceBits = bits and ((1u shl inlineBitCount) - 1u)
                bits = bits shr inlineBitCount
                renormalize()
                if (bitCount >= 16) distanceBits = (distanceBits shl 16) or readUShort()
                val distance = (32u shl bitCount) + (distanceBits shl 5) +
                    lowSymbol.toUInt() - 39u
                if (distance == 0u || distance > Int.MAX_VALUE.toUInt()) {
                    throw DecompressionException("Invalid Bitknit match distance")
                }
                matchDistance = distance.toInt()
                val first = ((recentMask shr 21) and 7u).toInt()
                val second = ((recentMask shr 18) and 7u).toInt()
                state.recentDistances[first] = state.recentDistances[second]
                state.recentDistances[second] = matchDistance
            } else {
                val shift = 3 * lowSymbol
                val recentIndex = ((recentMask shr shift) and 7u).toInt()
                matchDistance = state.recentDistances[recentIndex]
                val preserved = 0xfffffff8u shl shift
                recentMask = (recentMask and preserved) or
                    ((recentIndex.toUInt() + 8u * recentMask) and preserved.inv())
            }

            copy(matchDistance, copyLength, decodedEnd)
            state.lastMatchDistance = matchDistance
        }

        if (outputPosition != decodedEnd) throw DecompressionException("Bitknit output size mismatch")
        writeUShort(bits)
        writeUShort(bits2)
        if (outputPosition != outputSize) throw DecompressionException("Bitknit output size mismatch")
        if (inputPosition != inputSize) throw DecompressionException("Unused Bitknit input")
        state.recentDistanceMask = recentMask
    }

    private fun lookupLiteral(): Int {
        val decoded = state.literals[absolutePosition().toInt() and 3].decode(bits)
        bits = (decoded ushr 32).toUInt()
        return decoded.toInt()
    }

    private fun lookupDistanceLowBits(): Int {
        val decoded = state.distanceLowBits[absolutePosition().toInt() and 3].decode(bits)
        bits = (decoded ushr 32).toUInt()
        return decoded.toInt()
    }

    private fun lookupDistanceBitCount(): Int {
        val decoded = state.distanceBitCounts.decode(bits)
        bits = (decoded ushr 32).toUInt()
        return decoded.toInt()
    }

    private fun renormalize() {
        if (bits < 0x10000u) bits = (bits shl 16) or readUShort()
        val previous = bits
        bits = bits2
        bits2 = previous
    }

    private fun writeLiteral(symbol: Int) {
        val reference = previous(state.lastMatchDistance).toInt() and 255
        write((symbol + reference) and 255)
    }

    private fun copy(distance: Int, length: Int, limit: Int) {
        if (length > limit - outputPosition) throw DecompressionException("Bitknit match exceeds output")
        repeat(length) { write(previous(distance).toInt() and 255) }
    }

    private fun previous(distance: Int): Byte {
        if (distance <= 0) throw DecompressionException("Invalid Bitknit match distance")
        return if (distance <= outputPosition) output[outputPosition - distance]
        else history.previousStream(distance - outputPosition)
    }

    private fun absolutePosition(): Long = outputBase + outputPosition

    private fun write(value: Int) {
        if (outputPosition >= outputSize) throw DecompressionException("Bitknit output exceeds quantum")
        output[outputPosition++] = value.toByte()
    }

    private fun writeUShort(value: UInt) {
        write(value.toInt())
        write((value shr 8).toInt())
    }

    private fun readUShort(): UInt {
        if (inputSize - inputPosition < 2) throw DecompressionException("Truncated Bitknit input")
        val value = (input[inputPosition].toUInt() and 255u) or
            ((input[inputPosition + 1].toUInt() and 255u) shl 8)
        inputPosition += 2
        return value
    }

    private fun readUInt(): UInt {
        if (inputSize - inputPosition < 4) throw DecompressionException("Truncated Bitknit input")
        var value = 0u
        repeat(4) { shift ->
            value = value or ((input[inputPosition + shift].toUInt() and 255u) shl (shift * 8))
        }
        inputPosition += 4
        return value
    }
}
