package com.uselessmnemonic.koodle.internal

import com.uselessmnemonic.koodle.DecompressionException

internal sealed interface QuantumHeader {
    data class Compressed(val size: Int, val checksum: Int? = null) : QuantumHeader
    data class Fill(val value: Byte) : QuantumHeader
    data class WholeMatch(val distance: Long) : QuantumHeader
    data object Uncompressed : QuantumHeader
}

/** Incremental big-endian quantum header parser; retains no payload bytes. */
internal class QuantumHeaderParser {
    private enum class State { HEADER, CHECKSUM, FILL, MATCH_HIGH, MATCH_LOW, MATCH_EXTENSION }
    private var state = State.HEADER
    private var large = true
    private var checksummed = false
    private var value = 0
    private var count = 0
    private var compressedSize = 0
    private var extension = 0L
    private var shift = 0

    fun reset(large: Boolean, checksummed: Boolean = false) {
        this.large = large
        this.checksummed = checksummed
        state = State.HEADER
        value = 0
        count = 0
        compressedSize = 0
        extension = 0
        shift = 0
    }

    private fun complete(header: QuantumHeader): QuantumHeader {
        reset(large, checksummed)
        return header
    }

    /** Returns null until a complete header is available. Resets after each header. */
    fun accept(byte: Byte): QuantumHeader? {
        val unsigned = byte.toInt() and 0xff
        when (state) {
            State.CHECKSUM -> {
                value = (value shl 8) or unsigned
                if (++count < 3) return null
                return complete(QuantumHeader.Compressed(compressedSize, value))
            }
            State.FILL -> return complete(QuantumHeader.Fill(byte))
            State.MATCH_HIGH -> {
                value = unsigned shl 8
                state = State.MATCH_LOW
                return null
            }
            State.MATCH_LOW -> {
                value = value or unsigned
                if (value >= 0x8000) return complete(QuantumHeader.WholeMatch((value - 0x8000 + 1).toLong()))
                state = State.MATCH_EXTENSION
                return null
            }
            State.MATCH_EXTENSION -> {
                val base = value + 0x8001L
                val limit = (Long.MAX_VALUE - base) ushr 15
                val term = if (unsigned < 0x80) unsigned + 0x80L else unsigned - 0x80L
                if (shift >= 63 || term > ((limit - extension) ushr shift)) {
                    throw DecompressionException("Whole-match distance overflows Long")
                }
                extension += term shl shift
                if (unsigned >= 0x80) return complete(QuantumHeader.WholeMatch(base + (extension shl 15)))
                shift += 7
                return null
            }
            State.HEADER -> Unit
        }
        value = (value shl 8) or unsigned
        if (++count < if (large) 3 else 2) return null
        val mask = if (large) 0x3ffff else 0x3fff
        val size = value and mask
        if (size != mask) {
            if (!checksummed) return complete(QuantumHeader.Compressed(size + 1))
            compressedSize = size + 1
            value = 0
            count = 0
            state = State.CHECKSUM
            return null
        }
        val kind = value ushr if (large) 18 else 14
        if (kind == 1) {
            state = State.FILL
            return null
        }
        if (!large && kind == 2) return complete(QuantumHeader.Uncompressed)
        if (!large && kind == 0) {
            state = State.MATCH_HIGH
            return null
        }
        throw DecompressionException("Invalid quantum header: $value")
    }
}
