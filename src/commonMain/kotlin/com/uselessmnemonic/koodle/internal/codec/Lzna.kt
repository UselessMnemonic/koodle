package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory

private val literalStateTransitions: IntArray =
    intArrayOf(0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5)

internal class NibbleModel {
    val probabilities: IntArray = IntArray(16) { it * 0x800 }
}

internal class ThreeBitModel {
    val probabilities: IntArray = IntArray(8) { it * 0x1000 }
}

internal class LiteralModel {
    val upper: Array<NibbleModel> = Array(16) { NibbleModel() }
    val lower: Array<NibbleModel> = Array(16) { NibbleModel() }
    val noMatch: Array<NibbleModel> = Array(16) { NibbleModel() }
}

internal class FarDistanceModel {
    val firstLow: NibbleModel = NibbleModel()
    val firstHigh: NibbleModel = NibbleModel()
    val second: IntArray = IntArray(31) { 0x2000 }
    val third: Array<IntArray> = Array(2) { IntArray(31) { 0x2000 } }
}

internal class NearDistanceModel {
    val first: NibbleModel = NibbleModel()
    val second: IntArray = IntArray(16) { 0x2000 }
    val third: Array<IntArray> = Array(2) { IntArray(16) { 0x2000 } }
}

internal class LowDistanceBitsModel {
    val nibbles: Array<NibbleModel> = Array(2) { NibbleModel() }
    val bit: IntArray = intArrayOf(0x2000)
}

internal class RecentShortLengthModel {
    val lengths: Array<ThreeBitModel> = Array(4) { ThreeBitModel() }
}

internal class LongLengthModel {
    val first: Array<NibbleModel> = Array(4) { NibbleModel() }
    val second: NibbleModel = NibbleModel()
    val third: NibbleModel = NibbleModel()
}

/** Adaptive model retained across LZNA quanta and replaced at codec restarts. */
internal class LznaState {
    val matchHistory: IntArray = IntArray(8) { 1 }
    val literals: Array<LiteralModel> = Array(4) { LiteralModel() }
    val isLiteral: IntArray = IntArray(12 * 8) { 0x1000 }
    val types: Array<NibbleModel> = Array(12 * 8) { NibbleModel() }
    val recentShortLengths: Array<RecentShortLengthModel> =
        Array(4) { RecentShortLengthModel() }
    val recentLongLength: LongLengthModel = LongLengthModel()
    val lowDistanceBits: Array<LowDistanceBitsModel> = Array(2) { LowDistanceBitsModel() }
    val shortLengths: Array<IntArray> = Array(12) { IntArray(4) { 0x2000 } }
    val nearDistances: Array<NearDistanceModel> = Array(2) { NearDistanceModel() }
    val mediumLength: ThreeBitModel = ThreeBitModel()
    val longLength: LongLengthModel = LongLengthModel()
    val farDistance: FarDistanceModel = FarDistanceModel()

    fun preprocessMatchHistory() {
        if (matchHistory[4] < 0xc000) return
        var index = 0
        while (matchHistory[4 + index] >= 0xc000) {
            index++
            if (index >= 4) {
                matchHistory[7] = matchHistory[6]
                matchHistory[6] = matchHistory[5]
                matchHistory[5] = matchHistory[4]
                matchHistory[4] = 4
                return
            }
        }
        val selected = matchHistory[index + 4]
        for (position in index + 4 downTo 5) {
            matchHistory[position] = matchHistory[position - 1]
        }
        matchHistory[4] = selected
    }
}

internal fun decodeLznaQuantum(
    input: ByteArray,
    inputSize: Int,
    output: ByteArray,
    outputSize: Int,
    state: LznaState,
    history: DecodeHistory,
) {
    require(inputSize in 0..input.size)
    require(outputSize in 0..output.size)
    if (outputSize < 8) throw DecompressionException("LZNA quantum is too short")
    LznaDecoder(input, inputSize, output, outputSize, state, history).decode()
}

private class LznaDecoder(
    private val input: ByteArray,
    private val inputSize: Int,
    private val output: ByteArray,
    private val outputSize: Int,
    private val state: LznaState,
    private val history: DecodeHistory,
) {
    private var inputPosition = 0
    private var outputPosition = 0
    private val outputBase = history.outputCount
    private var bitsA = 0uL
    private var bitsB = 0uL

    fun decode() {
        state.preprocessMatchHistory()
        bitsA = initializeBits()
        bitsB = initializeBits()
        var distance = state.matchHistory[4]
        var decoderState = 5
        val decodedEnd = outputSize - 8

        if (outputBase == 0L) {
            if (decodedEnd <= 0) throw DecompressionException("LZNA initial quantum is too short")
            val value = if (readBoolean()) {
                0
            } else {
                val model = state.literals[0]
                val upper = readNibble(model.upper[0])
                (upper shl 4) + readNibble(if (upper != 0) model.noMatch[upper] else model.lower[0])
            }
            write(value)
        }

        while (outputPosition < decodedEnd) {
            val matchValue = previous(distance)
            val context = (absolutePosition().toInt() and 7) + 8 * decoderState
            if (readBit(state.isLiteral, context, 13, 5) != 0) {
                val type = readNibble(state.types[context])
                when {
                    type == 0 -> {
                        write(matchValue.toInt() and 255)
                        decoderState = if (decoderState >= 7) 11 else 9
                    }
                    type < 4 -> {
                        val length = when (type) {
                            1 -> 3 + readBit(
                                state.shortLengths[decoderState],
                                absolutePosition().toInt() and 3,
                                14,
                                4,
                            )
                            2 -> 5 + readThreeBits(state.mediumLength)
                            else -> readLength(state.longLength) + 13
                        }
                        distance = if (type == 1) {
                            readNearDistance(length - 3)
                        } else {
                            readFarDistance()
                        }
                        copy(distance, length, decodedEnd)
                        decoderState = if (decoderState >= 7) 10 else 7
                        state.matchHistory[7] = state.matchHistory[6]
                        state.matchHistory[6] = state.matchHistory[5]
                        state.matchHistory[5] = state.matchHistory[4]
                        state.matchHistory[4] = distance
                    }
                    type >= 12 -> {
                        val index = type - 12
                        distance = selectRecentDistance(index)
                        copy(distance, 2, decodedEnd)
                        decoderState = if (decoderState >= 7) 11 else 8
                    }
                    else -> {
                        val index = (type - 4) ushr 1
                        distance = selectRecentDistance(index)
                        val length = if (type and 1 != 0) {
                            11 + readLength(state.recentLongLength)
                        } else {
                            3 + readThreeBits(
                                state.recentShortLengths[index]
                                    .lengths[absolutePosition().toInt() and 3],
                            )
                        }
                        copy(distance, length, decodedEnd)
                        decoderState = if (decoderState >= 7) 11 else 8
                    }
                }
            } else {
                val model = state.literals[absolutePosition().toInt() and 3]
                val match = matchValue.toInt() and 255
                val upper = readNibble(model.upper[match ushr 4])
                val lowerModel = if (match ushr 4 != upper) model.noMatch[upper]
                    else model.lower[match and 15]
                write((upper shl 4) + readNibble(lowerModel))
                decoderState = literalStateTransitions[decoderState]
            }
        }
        if (outputPosition != decodedEnd) throw DecompressionException("LZNA match exceeds output")
        writeState(bitsA)
        writeState(bitsB)
        if (outputPosition != outputSize) throw DecompressionException("LZNA output size mismatch")
        if (inputPosition != inputSize) throw DecompressionException("Unused LZNA input")
    }

    private fun absolutePosition(): Long = outputBase + outputPosition

    private fun selectRecentDistance(index: Int): Int {
        if (index !in 0..3) throw DecompressionException("Invalid LZNA recent distance")
        val distance = state.matchHistory[4 + index]
        state.matchHistory[4 + index] = state.matchHistory[3 + index]
        state.matchHistory[3 + index] = state.matchHistory[2 + index]
        state.matchHistory[2 + index] = state.matchHistory[1 + index]
        state.matchHistory[4] = distance
        return distance
    }

    private fun previous(distance: Int): Byte {
        if (distance <= 0) throw DecompressionException("Invalid LZNA match distance")
        return if (distance <= outputPosition) {
            output[outputPosition - distance]
        } else {
            val historyDistance = distance - outputPosition
            if (historyDistance.toLong() > outputBase) {
                throw DecompressionException(
                    "LZNA match distance $distance exceeds ${absolutePosition()} bytes of output",
                )
            }
            history.previousStream(historyDistance)
        }
    }

    private fun copy(distance: Int, length: Int, limit: Int) {
        if (length < 0 || length > limit - outputPosition) {
            throw DecompressionException("LZNA match exceeds output")
        }
        repeat(length) { write(previous(distance).toInt() and 255) }
    }

    private fun write(value: Int) {
        if (outputPosition >= outputSize) throw DecompressionException("LZNA output exceeds quantum")
        output[outputPosition++] = value.toByte()
    }

    private fun writeState(value: ULong) {
        repeat(4) { shift -> write((value shr (shift * 8)).toInt()) }
    }

    private fun initializeBits(): ULong {
        val descriptor = readByte()
        val byteCount = descriptor ushr 4
        if (byteCount > 8) throw DecompressionException("Invalid LZNA state width")
        var value = 0uL
        repeat(byteCount) { value = (value shl 8) or readByte().toULong() }
        return (value shl 4) or (descriptor and 15).toULong()
    }

    private fun readByte(): Int {
        if (inputPosition >= inputSize) throw DecompressionException("Truncated LZNA input")
        return input[inputPosition++].toInt() and 255
    }

    private fun readLittleEndianInt(): ULong {
        if (inputSize - inputPosition < 4) throw DecompressionException("Truncated LZNA state")
        var value = 0uL
        repeat(4) { shift -> value = value or (readByte().toULong() shl (shift * 8)) }
        return value
    }

    private fun renormalize() {
        var value = bitsA
        if (value < 0x80000000uL) value = (value shl 32) or readLittleEndianInt()
        bitsA = bitsB
        bitsB = value
    }

    private fun readBoolean(): Boolean {
        val result = bitsA and 1uL
        bitsA = bitsA shr 1
        renormalize()
        return result != 0uL
    }

    private fun readBits(count: Int): Int {
        if (count !in 0..31) throw DecompressionException("Invalid LZNA bit count")
        val mask = if (count == 0) 0uL else (1uL shl count) - 1uL
        val result = bitsA and mask
        bitsA = bitsA shr count
        renormalize()
        return result.toInt()
    }

    private fun readNibble(model: NibbleModel): Int =
        readAdaptiveSymbol(model.probabilities, 0x7fd9)

    private fun readThreeBits(model: ThreeBitModel): Int =
        readAdaptiveSymbol(model.probabilities, 0x7fe5)

    private fun readAdaptiveSymbol(probabilities: IntArray, updateTarget: Int): Int {
        val stateValue = bitsA
        val slot = (stateValue and 0x7fffuL).toInt()
        var boundary = 1
        while (boundary < probabilities.size && probabilities[boundary] <= slot) boundary++
        val symbol = boundary - 1
        val start = probabilities[symbol]
        val end = if (boundary < probabilities.size) probabilities[boundary] else 0x8000
        probabilities.indices.forEach { index ->
            val target = index * 8 + if (probabilities[index] > slot) updateTarget else 0
            probabilities[index] += (target - probabilities[index]) shr 7
        }
        bitsA = (end - start).toULong() * (stateValue shr 15) +
            (stateValue and 0x7fffuL) - start.toULong()
        renormalize()
        return symbol
    }

    private fun readBit(models: IntArray, index: Int, bitCount: Int, shift: Int): Int {
        var probability = models[index]
        val magnitude = 1uL shl bitCount
        val scaled = probability.toULong() * (bitsA shr bitCount)
        val result: Int
        if ((bitsA and (magnitude - 1uL)) >= probability.toULong()) {
            bitsA -= scaled + probability.toULong()
            probability -= probability shr shift
            result = 1
        } else {
            bitsA = (bitsA and (magnitude - 1uL)) + scaled
            probability += ((magnitude - probability.toULong()) shr shift).toInt()
            result = 0
        }
        models[index] = probability
        renormalize()
        return result
    }

    private fun readFarDistance(): Int {
        var bitCount = readNibble(state.farDistance.firstLow)
        if (bitCount >= 15) bitCount = 15 + readNibble(state.farDistance.firstHigh)
        val high = readDistanceHighBits(
            bitCount,
            state.farDistance.second,
            state.farDistance.third,
        )
        return readDistanceLowBits(high)
    }

    private fun readNearDistance(index: Int): Int {
        val model = state.nearDistances[index]
        val bitCount = readNibble(model.first)
        val high = readDistanceHighBits(bitCount, model.second, model.third)
        return readDistanceLowBits(high)
    }

    private fun readDistanceHighBits(
        bitCount: Int,
        second: IntArray,
        third: Array<IntArray>,
    ): Int {
        if (bitCount == 0) return 0
        if (bitCount - 1 !in second.indices) throw DecompressionException("Invalid LZNA distance")
        var high = readBit(second, bitCount - 1, 14, 6) + 2
        if (bitCount != 1) {
            high = (high shl 1) + readBit(third[high - 2], bitCount - 1, 14, 6)
            if (bitCount != 2) high = (high shl (bitCount - 2)) + readBits(bitCount - 2)
        }
        return high - 1
    }

    private fun readDistanceLowBits(high: Int): Int {
        val model = state.lowDistanceBits[if (high == 0) 1 else 0]
        val lowBit = readBit(model.bit, 0, 14, 6)
        val lowNibble = readNibble(model.nibbles[lowBit])
        return lowBit + 2 * lowNibble + 32 * high + 1
    }

    private fun readLength(model: LongLengthModel): Int {
        var length = readNibble(model.first[absolutePosition().toInt() and 3])
        if (length >= 12) {
            var value = readNibble(model.second)
            if (value >= 15) value = 15 + readNibble(model.third)
            val bitCount: Int
            val base: Int
            if (value == 0) {
                bitCount = 0
                base = 0
            } else {
                bitCount = (value - 1) ushr 1
                base = ((((value - 1) and 1) + 2) shl bitCount) - 1
            }
            length += (readBits(bitCount) + base) * 4
        }
        return length
    }
}
