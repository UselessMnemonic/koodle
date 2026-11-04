package com.uselessmnemonic.koodle.internal.entropy

import com.uselessmnemonic.koodle.DecompressionException
import com.uselessmnemonic.koodle.internal.DecodeHistory
import com.uselessmnemonic.koodle.internal.codec.decodeKrakenChunk
import com.uselessmnemonic.koodle.internal.codec.decodeLeviathanChunk
import com.uselessmnemonic.koodle.internal.codec.decodeMermaidChunk

/** Shared 128 KiB framing plus dispatch to algorithm-specific LZ command processors. */
internal fun decodeStoredQuantum(
    input: ByteArray, inputSize: Int, output: ByteArray, outputSize: Int,
    decoderType: Int, workspace: EntropyWorkspace, codecScratch: EntropyWorkspace,
    history: DecodeHistory,
) {
    var source = 0
    var destination = 0
    while (destination < outputSize) {
        val count = minOf(0x20000, outputSize - destination)
        if (inputSize - source < 3) throw DecompressionException("Truncated large-quantum chunk header")
        val bits = ((input[source].toInt() and 255) shl 16) or
            ((input[source + 1].toInt() and 255) shl 8) or (input[source + 2].toInt() and 255)
        if (bits and 0x800000 == 0) {
            val header = decodeByteArray(
                input, source, inputSize, output, destination, destination + count, workspace,
            )
            if (header.decodedSize != count) throw DecompressionException("Chunk output size mismatch")
            source += header.headerSize + header.encodedSize
        } else {
            source += 3
            val size = bits and 0x7ffff
            val mode = (bits ushr 19) and 15
            if (size > inputSize - source) throw DecompressionException("Truncated chunk payload")
            if (size > count) throw DecompressionException("Chunk payload exceeds output size")
            if (size < count) {
                when (decoderType) {
                    6 -> decodeKrakenChunk(
                        input, source, source + size, output, destination, count, mode, workspace, history,
                    )
                    10 -> decodeMermaidChunk(
                        input, source, source + size, output, destination, count, mode, workspace, history,
                    )
                    12 -> decodeLeviathanChunk(
                        input, source, source + size, output, destination, count, mode,
                        workspace, codecScratch, history,
                    )
                    else -> throw UnsupportedOperationException(
                        "LZ commands for decoder $decoderType are not supported yet",
                    )
                }
            } else {
                if (mode != 0) throw DecompressionException("Invalid raw chunk mode")
                input.copyInto(output, destination, source, source + size)
            }
            source += size
        }
        destination += count
    }
    if (source != inputSize) throw DecompressionException("Unused bytes in large quantum")
}
