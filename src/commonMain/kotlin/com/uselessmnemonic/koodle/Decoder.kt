package com.uselessmnemonic.koodle

/** A stateful, incremental decoding operation. Instances must not be used concurrently. */
public interface Decoder {
    /**
     * Consumes and produces only within the supplied half-open ranges. Arrays must not alias.
     * No arrays are retained: advance by the returned counts and resubmit any unconsumed input.
     * [endOfInput] means there are no bytes after this input range, including on subsequent calls.
     * Output exhaustion can leave final input unconsumed; resubmit it with [endOfInput] still true.
     * Empty ranges are allowed. A finished decoder consumes nothing further.
     *
     * The caller owns all buffers and I/O resources; the decoder opens or closes none.
     * Invalid arguments throw [IllegalArgumentException] without changing decoder state.
     * Decoding errors may leave partial output; discard the decoder after a decoding error.
     */
    public fun decode(
        source: ByteArray,
        destination: ByteArray,
        startIndex: Int = 0,
        endIndex: Int = source.size,
        destinationStartIndex: Int = 0,
        destinationEndIndex: Int = destination.size,
        endOfInput: Boolean = false,
    ): DecodeResult
}

/** Counts are relative to the ranges passed to [Decoder.decode]. */
public data class DecodeResult(
    public val bytesConsumed: Int,
    public val bytesWritten: Int,
    public val status: DecodeStatus,
)

public enum class DecodeStatus {
    /** Supply more input, preserving any unconsumed bytes. */
    NEEDS_INPUT,
    /** Supply output capacity, preserving any unconsumed input. */
    NEEDS_OUTPUT,
    /** The expected output has been produced; trailing input was not consumed. */
    FINISHED,
}

/** Malformed or truncated compressed data, rather than an invalid API argument. */
public class DecompressionException(message: String) : Exception(message)
