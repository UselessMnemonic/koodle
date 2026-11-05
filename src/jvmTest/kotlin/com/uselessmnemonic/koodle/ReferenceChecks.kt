package com.uselessmnemonic.koodle

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.name

/** Runs the port against oozextract's optional, externally supplied reference corpus. */
public fun main(arguments: Array<String>) {
    require(arguments.size == 1) { "Expected the oozextract repository path" }
    val root = Path.of(arguments.single())
    val testdata = root.resolve("testdata")
    val verify = root.resolve("verify")
    require(Files.isDirectory(testdata) && Files.isDirectory(verify)) {
        "$root does not contain oozextract testdata and verify directories"
    }

    var checked = 0
    Files.list(testdata).use { paths ->
        paths.sorted().forEach { compressedFile ->
            val file = Files.readAllBytes(compressedFile)
            require(file.size > 8) { "Truncated corpus file: $compressedFile" }
            val shortHeader = (file[4].toInt() and 255) == 0x8c
            val outputSize = file.readLittleEndianInt(0)
            require(outputSize >= 0 && (shortHeader || file.readLittleEndianInt(4) == 0)) {
                "Corpus output does not fit in a Kotlin ByteArray: $compressedFile"
            }
            val inputStart = if (shortHeader) 4 else 8
            val input = file.copyOfRange(inputStart, file.size)
            val actual = ByteArray(outputSize)
            val decoder = OozDecoder(outputSize.toLong(), maxOf(0x10000, outputSize))
            var consumed = 0
            var written = 0
            var calls = 0
            while (true) {
                check(++calls <= input.size + outputSize + 1) { "Decoder made no progress" }
                val inputEnd = minOf(input.size, consumed + 257)
                val outputEnd = minOf(actual.size, written + 1009)
                val result = decoder.decode(
                    input, actual, consumed, inputEnd, written, outputEnd,
                    endOfInput = inputEnd == input.size,
                )
                consumed += result.bytesConsumed
                written += result.bytesWritten
                if (result.status == DecodeStatus.FINISHED) break
                check(result.bytesConsumed != 0 || result.bytesWritten != 0) {
                    "Decoder stalled on $compressedFile"
                }
            }

            val expectedName = compressedFile.name.substringBeforeLast('.')
            val expected = Files.readAllBytes(verify.resolve(expectedName))
            val mismatch = actual.indices.firstOrNull { it >= expected.size || actual[it] != expected[it] }
            check(mismatch == null && actual.size == expected.size) {
                "$compressedFile differs at ${mismatch ?: minOf(actual.size, expected.size)} " +
                    "(actual size ${actual.size}, expected size ${expected.size})"
            }
            check(consumed == input.size && written == actual.size)
            checked++
        }
    }
    println("Verified $checked oozextract reference corpus files")
}

private fun ByteArray.readLittleEndianInt(index: Int): Int =
    (this[index].toInt() and 255) or
        ((this[index + 1].toInt() and 255) shl 8) or
        ((this[index + 2].toInt() and 255) shl 16) or
        ((this[index + 3].toInt() and 255) shl 24)
