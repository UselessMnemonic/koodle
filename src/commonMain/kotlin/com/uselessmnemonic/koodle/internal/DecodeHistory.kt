package com.uselessmnemonic.koodle.internal

import com.uselessmnemonic.koodle.DecompressionException

/** Bounded stream history; codec restarts restrict LZ references without erasing framing history. */
internal class DecodeHistory(capacity: Int) {
    private val bytes = ByteArray(capacity)
    private var next = 0
    private var available = 0
    private var codecHasOutput = false
    private var codecTotal = 0L
    private var total = 0L

    fun restartCodec() {
        codecHasOutput = false
        codecTotal = 0
    }

    val hasCodecOutput: Boolean get() = codecHasOutput
    val codecOutputCount: Long get() = codecTotal
    val outputCount: Long get() = total

    fun append(value: Byte) {
        bytes[next] = value
        if (++next == bytes.size) next = 0
        if (available < bytes.size) available++
        codecHasOutput = true
        codecTotal++
        total++
    }

    fun append(source: ByteArray, start: Int, end: Int) {
        for (index in start until end) append(source[index])
    }

    fun previous(distance: Int): Byte {
        if (distance <= 0 || distance.toLong() > codecTotal) {
            throw DecompressionException("Codec match precedes the restart boundary")
        }
        if (distance > bytes.size) {
            throw UnsupportedOperationException(
                "Codec match distance $distance exceeds history capacity ${bytes.size}; increase historyCapacity",
            )
        }
        return previousWholeMatch(distance)
    }

    fun previousStream(distance: Int): Byte {
        if (distance <= 0 || distance.toLong() > total) {
            throw DecompressionException("Match precedes the stream output")
        }
        if (distance > bytes.size) {
            throw UnsupportedOperationException(
                "Match distance $distance exceeds history capacity ${bytes.size}; increase historyCapacity",
            )
        }
        return previousWholeMatch(distance)
    }

    fun validateWholeMatch(distance: Long) {
        if (distance <= 0 || distance > total) {
            throw DecompressionException("Whole match precedes the stream output")
        }
        if (distance > available) {
            throw UnsupportedOperationException(
                "Whole-match distance $distance exceeds history capacity ${bytes.size}; increase historyCapacity",
            )
        }
    }

    /** [validateWholeMatch] must succeed before starting the match. */
    fun previousWholeMatch(distance: Int): Byte {
        val index = next - distance
        return bytes[if (index < 0) index + bytes.size else index]
    }
}
