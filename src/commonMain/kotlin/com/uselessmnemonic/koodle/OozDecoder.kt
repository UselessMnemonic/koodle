package com.uselessmnemonic.koodle

import com.uselessmnemonic.koodle.internal.QuantumHeader
import com.uselessmnemonic.koodle.internal.QuantumHeaderParser
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.codec.BitknitState
import com.uselessmnemonic.koodle.internal.codec.LznaState
import com.uselessmnemonic.koodle.internal.codec.decodeBitknitQuantum
import com.uselessmnemonic.koodle.internal.codec.decodeLzb16
import com.uselessmnemonic.koodle.internal.codec.decodeLznaQuantum
import com.uselessmnemonic.koodle.internal.entropy.decodeStoredQuantum
import com.uselessmnemonic.koodle.internal.entropy.EntropyWorkspace

/**
 * Decodes Oodle block framing with an exact [outputSize] supplied by its enclosing container.
 * Supports LZB16, LZNA, Bitknit, raw blocks, fills, whole matches, and uncompressed small quanta.
 * Large quanta support every byte-array entropy encoding and the traditional
 * Kraken and Mermaid/Selkie LZ command paths plus all six Leviathan literal
 * modes, multi-array commands, recursive packed metadata, and Kraken excess-byte
 * streams. Checksums throw [UnsupportedOperationException]. Codec and byte-array decoding
 * are separate from framing.
 *
 * Input and output can be supplied in bounded chunks, even for sizes exceeding array limits.
 * Working memory is bounded by [historyCapacity] (default 64 KiB, minimum 64 KiB)
 * plus two lazy quantum buffers (16 KiB each for small codecs, up to 256 KiB each
 * for large quanta) and up to two lazy 256 KiB entropy arenas. Whole matches may reference output before
 * a codec restart. Distances beyond retained history throw [UnsupportedOperationException];
 * select a larger capacity before decoding if required by the input.
 */
public class OozDecoder(outputSize: Long, historyCapacity: Int = 0x10000) : Decoder {
    init {
        require(outputSize >= 0) { "outputSize must be non-negative" }
        require(historyCapacity >= 0x10000) { "historyCapacity must be at least 65536 bytes" }
    }

    private var remaining = outputSize
    private var firstHeaderByte = -1
    private var blockRemaining = 0
    private var quantumSize = 0
    private var quantumRemaining = 0
    private var quantum: QuantumHeader? = null
    private val quantumParser = QuantumHeaderParser()
    private var decoderType = 0
    private val history = DecodeHistory(historyCapacity)
    private var compressed: ByteArray? = null
    private var decoded: ByteArray? = null
    private var compressedCount = 0
    private var decodedOffset = 0
    private var quantumDecoded = false
    private val entropyWorkspace = EntropyWorkspace()
    private val codecScratchWorkspace = EntropyWorkspace()
    private var lznaState: LznaState? = null
    private var bitknitState: BitknitState? = null
    private var failed = false

    private fun advanceOutput(count: Int) {
        quantumRemaining -= count
        blockRemaining -= count
        remaining -= count
        if (quantumRemaining == 0) quantum = null
    }

    override fun decode(
        source: ByteArray,
        destination: ByteArray,
        startIndex: Int,
        endIndex: Int,
        destinationStartIndex: Int,
        destinationEndIndex: Int,
        endOfInput: Boolean,
    ): DecodeResult {
        require(startIndex >= 0 && endIndex >= startIndex && endIndex <= source.size) {
            "Invalid source range"
        }
        require(destinationStartIndex >= 0 && destinationEndIndex >= destinationStartIndex &&
            destinationEndIndex <= destination.size) { "Invalid destination range" }
        require(source !== destination) { "Source and destination must not alias" }
        check(!failed) { "Discard the decoder after a decoding error" }
        var input = startIndex
        var output = destinationStartIndex
        fun result(status: DecodeStatus): DecodeResult =
            DecodeResult(input - startIndex, output - destinationStartIndex, status)

        try {
            while (remaining > 0) {
                if (output == destinationEndIndex) return result(DecodeStatus.NEEDS_OUTPUT)
                // Fill output needs no input, including after the final input byte.
                val current = quantum
                if (current is QuantumHeader.Fill && quantumRemaining > 0) {
                    val count = minOf(quantumRemaining, destinationEndIndex - output)
                    destination.fill(current.value, output, output + count)
                    history.append(destination, output, output + count)
                    output += count
                    advanceOutput(count)
                    continue
                }
                if (current is QuantumHeader.WholeMatch) {
                    val count = minOf(quantumRemaining, destinationEndIndex - output)
                    repeat(count) {
                        val value = history.previousWholeMatch(current.distance.toInt())
                        destination[output++] = value
                        history.append(value)
                    }
                    advanceOutput(count)
                    continue
                }
                if (current is QuantumHeader.Compressed) {
                    val payload = compressed!!
                    val buffer = decoded!!
                    if (!quantumDecoded) {
                        val count = minOf(current.size - compressedCount, endIndex - input)
                        source.copyInto(payload, compressedCount, input, input + count)
                        compressedCount += count
                        input += count
                        if (compressedCount < current.size) {
                            if (endOfInput) throw DecompressionException("Truncated compressed quantum")
                            return result(DecodeStatus.NEEDS_INPUT)
                        }
                        if (decoderType == 2) {
                            decodeLzb16(payload, current.size, buffer, quantumRemaining, history)
                        } else if (decoderType == 5) {
                            val state = lznaState ?: LznaState().also { lznaState = it }
                            decodeLznaQuantum(
                                payload, current.size, buffer, quantumRemaining, state, history,
                            )
                            history.append(buffer, 0, quantumRemaining)
                        } else if (decoderType == 11) {
                            val state = bitknitState ?: BitknitState().also { bitknitState = it }
                            decodeBitknitQuantum(
                                payload, current.size, buffer, quantumRemaining, state, history,
                            )
                            history.append(buffer, 0, quantumRemaining)
                        } else {
                            decodeStoredQuantum(
                                payload, current.size, buffer, quantumRemaining, decoderType,
                                entropyWorkspace, codecScratchWorkspace, history,
                            )
                            history.append(buffer, 0, quantumRemaining)
                        }
                        quantumDecoded = true
                    }
                    val count = minOf(quantumRemaining, destinationEndIndex - output)
                    buffer.copyInto(destination, output, decodedOffset, decodedOffset + count)
                    decodedOffset += count
                    output += count
                    advanceOutput(count)
                    continue
                }
                if (input == endIndex) {
                    if (endOfInput) throw DecompressionException("Unexpected end of Oodle stream")
                    return result(DecodeStatus.NEEDS_INPUT)
                }
                if (blockRemaining == 0) {
                    if (firstHeaderByte < 0) {
                        firstHeaderByte = source[input++].toInt() and 0xff
                        if (firstHeaderByte and 0x3f != 0x0c) {
                            throw DecompressionException("Invalid Oodle block header")
                        }
                        continue
                    }
                    val second = source[input++].toInt() and 0xff
                    decoderType = second and 0x7f
                    quantumSize = when (decoderType) {
                        2, 5, 11 -> 0x4000
                        6, 10, 12 -> 0x40000
                        else -> throw DecompressionException("Unknown decoder type: ${second and 0x7f}")
                    }
                    if (second and 0x80 != 0) {
                        throw UnsupportedOperationException("Checksummed blocks are not supported yet")
                    }
                    // All decoder types receive a framing header every 256 KiB of output.
                    // Small codec quantum sizes do not introduce headers in raw blocks.
                    blockRemaining = minOf(remaining, 0x40000L).toInt()
                    if (firstHeaderByte and 0x80 != 0) {
                        history.restartCodec()
                        lznaState = null
                        bitknitState = null
                    }
                    quantumParser.reset(large = quantumSize == 0x40000)
                    if (firstHeaderByte and 0x40 != 0) {
                        quantum = QuantumHeader.Uncompressed
                        quantumRemaining = blockRemaining
                    }
                    firstHeaderByte = -1
                } else if (quantumRemaining == 0) {
                    val header = quantumParser.accept(source[input++]) ?: continue
                    when (header) {
                        is QuantumHeader.Compressed -> {
                            if (decoderType != 2 && decoderType != 5 && decoderType != 6 &&
                                decoderType != 10 && decoderType != 11 && decoderType != 12
                            ) throw UnsupportedOperationException(
                                "Compressed payloads for decoder $decoderType are not supported yet",
                            )
                            if ((compressed?.size ?: 0) < quantumSize) compressed = ByteArray(quantumSize)
                            if ((decoded?.size ?: 0) < quantumSize) decoded = ByteArray(quantumSize)
                            compressedCount = 0
                            decodedOffset = 0
                            quantumDecoded = false
                            quantum = header
                            quantumRemaining = minOf(quantumSize, blockRemaining)
                        }
                        is QuantumHeader.WholeMatch -> {
                            history.validateWholeMatch(header.distance)
                            quantum = header
                            quantumRemaining = minOf(quantumSize, blockRemaining)
                        }
                        is QuantumHeader.Fill, QuantumHeader.Uncompressed -> {
                            quantum = header
                            quantumRemaining = minOf(quantumSize, blockRemaining)
                        }
                    }
                } else {
                    val count = minOf(quantumRemaining, endIndex - input, destinationEndIndex - output)
                    source.copyInto(destination, output, input, input + count)
                    history.append(source, input, input + count)
                    input += count
                    output += count
                    advanceOutput(count)
                }
            }
            return result(DecodeStatus.FINISHED)
        } catch (error: DecompressionException) {
            failed = true
            throw error
        } catch (error: UnsupportedOperationException) {
            failed = true
            throw error
        }
    }
}
