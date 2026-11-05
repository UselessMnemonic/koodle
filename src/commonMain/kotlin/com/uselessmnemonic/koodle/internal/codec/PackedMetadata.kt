package com.uselessmnemonic.koodle.internal.codec

import com.uselessmnemonic.koodle.DecompressionException

internal enum class BitstreamEnd { FORWARD, BACKWARD }

/** Reference-shaped two-ended reader used by packed offset and length streams. */
internal class TwoEndedBitReader(
    private val source: ByteArray,
    private val start: Int,
    private val end: Int,
    private val formatName: String,
) {
    private var forwardPosition = 0
    private var backwardPosition = 0

    fun read(count: Int, from: BitstreamEnd): Int {
        if (count < 0 || forwardPosition + backwardPosition > (end - start) * 8 - count) {
            throw DecompressionException("$formatName variable-bit streams overlap")
        }
        var value = 0
        repeat(count) {
            val position = when (from) {
                BitstreamEnd.FORWARD -> forwardPosition++
                BitstreamEnd.BACKWARD -> backwardPosition++
            }
            val index = when (from) {
                BitstreamEnd.FORWARD -> start + position / 8
                BitstreamEnd.BACKWARD -> end - 1 - position / 8
            }
            value = (value shl 1) or ((source[index].toInt() ushr (7 - position % 8)) and 1)
        }
        return value
    }

    fun readBackwardLengthCount(): Int {
        val zeroCount = readUnaryZeroCount(BitstreamEnd.BACKWARD, 12, "length count")
        return read(zeroCount, BitstreamEnd.BACKWARD)
            .withImplicitHighBit(zeroCount) - 1
    }

    fun readDistance(code: Int, from: BitstreamEnd): Int {
        val bitCount = code.traditionalDistanceBitCount()
        val lowBits = read(bitCount, from).withImplicitHighBit(bitCount)
        val tail = if (code < 0xf0) 0 else read(12, from)
        return lowBits.toTraditionalDistance(code, tail)
    }

    fun readScaledDistance(code: Int, from: BitstreamEnd): Int {
        val bitCount = code ushr 3
        if (bitCount > 26) throw DecompressionException("Invalid $formatName scaled offset")
        return read(bitCount, from).toScaledDistance(code)
    }

    fun readLength(from: BitstreamEnd): Int {
        val zeroCount = readUnaryZeroCount(from, 12, "extended length")
        return read(zeroCount + 6, from)
            .withImplicitHighBit(zeroCount + 6) - 64
    }

    private fun readUnaryZeroCount(from: BitstreamEnd, maximum: Int, valueName: String): Int {
        var count = 0
        while (read(1, from) == 0) {
            if (++count > maximum) throw DecompressionException("Invalid $formatName $valueName")
        }
        return count
    }

    fun requireConsumed() {
        val forwardBytes = (forwardPosition + 7) / 8
        val backwardBytes = (backwardPosition + 7) / 8
        if (forwardBytes + backwardBytes != end - start) {
            throw DecompressionException("Unused $formatName variable-bit bytes")
        }
    }
}

internal fun Int.withImplicitHighBit(bitCount: Int): Int = (1 shl bitCount) or this

internal fun Int.traditionalDistanceBitCount(): Int =
    if (this < 0xf0) (this ushr 4) + 4 else this - 0xf0 + 4

internal fun Int.toTraditionalDistance(code: Int, tail: Int): Int =
    if (code < 0xf0) this * 16 + (code and 15) - 248 else 8_322_816 + this * 4096 + tail

internal fun Int.toScaledDistance(code: Int): Int = ((8 + (code and 7)) shl (code ushr 3)) or this

internal fun Int.toRelativeOffset(): Int = 8 - this

internal fun Int.combineScaledOffset(scale: Int, lowBits: Int): Int = this * scale - lowBits

internal fun Int.expandPackedLength(extension: Int = 0): Int = this + extension + 3

internal data class UnpackedMetadata(val offsets: IntArray, val lengths: IntArray)

/** A detached two-ended stream containing only packed-length extensions. */
internal data class DetachedLengthBits(val start: Int, val end: Int)

/** Scalar equivalent of the reference implementation's `unpack_offsets`. */
internal fun unpackOffsets(
    packed: ByteArray,
    offsetsStart: Int,
    offsetsSize: Int,
    offsetLowBitsStart: Int,
    offsetScale: Int,
    lengthsStart: Int,
    lengthsSize: Int,
    variableBits: ByteArray,
    variableBitsStart: Int,
    variableBitsEnd: Int,
    formatName: String,
    detachedLengthBits: DetachedLengthBits? = null,
): UnpackedMetadata {
    val bits = TwoEndedBitReader(variableBits, variableBitsStart, variableBitsEnd, formatName)
    val extendedLengthCount = if (detachedLengthBits == null) {
        bits.readBackwardLengthCount()
    } else {
        var count = 0
        repeat(lengthsSize) { index ->
            if (packed[lengthsStart + index].toInt() and 255 == 255) count++
        }
        count
    }
    if (extendedLengthCount > 512) {
        throw DecompressionException("Too many $formatName extended lengths")
    }
    val offsets = IntArray(offsetsSize)
    repeat(offsetsSize) { index ->
        val code = packed[offsetsStart + index].toInt() and 255
        val from = if (index and 1 == 0) BitstreamEnd.FORWARD else BitstreamEnd.BACKWARD
        offsets[index] = if (offsetScale == 0) {
            -bits.readDistance(code, from)
        } else {
            val relative = bits.readScaledDistance(code, from).toRelativeOffset()
            if (offsetScale == 1) relative else relative.combineScaledOffset(
                offsetScale,
                packed[offsetLowBitsStart + index].toInt() and 255,
            )
        }
    }
    val lengthBits = detachedLengthBits?.let {
        TwoEndedBitReader(variableBits, it.start, it.end, "$formatName excess-length")
    } ?: bits
    val extended = IntArray(extendedLengthCount) { index ->
        lengthBits.readLength(if (index and 1 == 0) BitstreamEnd.FORWARD else BitstreamEnd.BACKWARD)
    }
    val lengths = IntArray(lengthsSize)
    var extensionIndex = 0
    repeat(lengthsSize) { index ->
        val packedLength = packed[lengthsStart + index].toInt() and 255
        val extension = if (packedLength == 255) {
            if (extensionIndex >= extended.size) {
                throw DecompressionException("Missing $formatName extended length")
            }
            extended[extensionIndex++]
        } else 0
        lengths[index] = packedLength.expandPackedLength(extension)
    }
    if (extensionIndex != extended.size) {
        throw DecompressionException("Unused $formatName extended lengths")
    }
    // The encoded excess form permits padding on both the main and detached seams.
    if (detachedLengthBits == null) bits.requireConsumed()
    return UnpackedMetadata(offsets, lengths)
}
