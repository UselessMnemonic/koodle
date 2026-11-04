package com.uselessmnemonic.koodle.internal

import com.uselessmnemonic.koodle.DecompressionException

/** Bounded stream history; codec restarts restrict LZB16 without erasing framing history. */
internal class DecodeHistory(capacity: Int) {
    private val bytes = ByteArray(capacity)
    private var next = 0
    private var available = 0
    private var sinceRestart = 0
    private var total = 0L

    fun restartCodec() { sinceRestart = 0 }

    fun append(value: Byte) {
        bytes[next] = value
        if (++next == bytes.size) next = 0
        if (available < bytes.size) available++
        if (sinceRestart < bytes.size) sinceRestart++
        total++
    }

    fun append(source: ByteArray, start: Int, end: Int) {
        for (index in start until end) append(source[index])
    }

    fun previous(distance: Int): Byte {
        if (distance !in 1..sinceRestart) throw DecompressionException("LZB16 match precedes available history")
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
