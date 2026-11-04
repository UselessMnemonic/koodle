# koodle

A Kotlin Multiplatform starting point for a port of
[oozextract](https://github.com/lvlvllvlvllvlvl/oozextract), under
`com.uselessmnemonic.koodle`. Supports LZB16 compressed quanta, raw blocks, fill
quanta, whole-match quanta, and uncompressed small quanta. The shared large-quantum
path also supports raw chunks and all byte-array entropy encodings under Kraken,
Mermaid/Selkie, and Leviathan framing. Both sparse and dense legacy Huffman
tables are supported for the three-stream and six-stream byte-array layouts,
including single-symbol fills. Newer Golomb-Rice Huffman tables and their compact
symbol-range maps are also supported. tANS arrays support both legacy and newer
Golomb-Rice table representations. Recursive arrays cover both sequential
concatenation and entropy-array interleaving. Kraken LZ chunks support ordinary
and delta literals, recent and traditional explicit offsets, and extended
lengths. Scaled Kraken offsets and Mermaid/Leviathan LZ commands remain
unsupported. Packed RLE command buffers may use any supported byte-array
encoding. Checksummed blocks are explicitly rejected.

## Build

Kotlin 2.4.21, Gradle 9.5.0, and JDK 17 or newer (JVM bytecode targets 17).
The library depends only on the Kotlin standard library and platform APIs.
Gradle and Kotlin compiler downloads are build tooling, not library dependencies.

```sh
./gradlew compileKotlinJvm compileKotlinLinuxArm64 compileKotlinMacosArm64
```

Build the macOS target on macOS with the Apple developer tools required by
Kotlin/Native. The first build downloads the Kotlin/Native toolchains.

## Decoding API

```kotlin
import com.uselessmnemonic.koodle.decompress
import com.uselessmnemonic.koodle.decompressInto

val decoded = decompress(compressed, outputSize = expectedSize)
val written = decompressInto(compressed, destination)
```

These eager conveniences delegate to `OozDecoder`, which implements the small
`Decoder` capability interface. The former scaffold `Decompressor` class has
been replaced by top-level functions. Source ranges use inclusive starts and
exclusive ends; destination offsets and exact output sizes avoid slice copies.
The enclosing container supplies the decoded size; container headers are not
input to the decoder. Eager operations ignore trailing input.

For incremental decoding, construct `OozDecoder(outputSize: Long)` and call
`decode` with input and output chunks. Advance by `bytesConsumed` and
`bytesWritten`; retain and resubmit any unconsumed input. `NEEDS_INPUT` requests
more input, `NEEDS_OUTPUT` requests destination capacity, and `FINISHED` leaves
trailing input untouched. Pass `endOfInput = true` when the supplied range is the
last input, and keep it true when resubmitting its unconsumed suffix. A truncated
final input throws `DecompressionException` once output capacity is available.

The decoder retains no caller arrays and owns no I/O resources. Arrays must not
alias, and instances must not be shared concurrently. Invalid arguments do not
change state. Malformed data or unsupported blocks invalidate the instance;
discard it after failure. Output can be partially modified on failure. A zero
output size finishes without consuming input.

The current implementation validates two-byte block headers, recognizes the six
Rust decoder IDs, and copies raw payloads, including across 256 KiB boundaries.
An internal incremental quantum-header parser uses sealed data variants for
compressed payload sizes, fill values, whole-match distances, and uncompressed
quanta. It handles
three-byte headers for large quanta and two-byte headers for small quanta.
Headers may span calls, including variable-length whole-match distances. Fill
and whole-match quanta can continue producing output after input is exhausted. LZB16 decoding lives separately from framing and handles literals,
length extensions, and forward-expanding overlapping matches. A bounded ring retains history across quanta. Codec restarts restrict LZB16
references to output since the restart, while whole-match framing can still
reference earlier stream output. All produced output feeds history.

Compressed input is buffered one quantum at a time, decoded into a reusable
output buffer, then drained into caller-provided chunks. LZB16 uses two 16 KiB
buffers; large quanta use two 256 KiB buffers. They are allocated lazily and
reused, requiring at most 512 KiB of working buffers plus history, independently
of stream size. The shared byte-array layer validates short/long headers and
encoded/decoded sizes. Its RLE decoder handles a single-byte fill, unpacked
commands, and raw nested command arrays without allocating scratch buffers.
Packed command arrays decode into a lazy, reusable 256 KiB entropy workspace;
their untouched suffix is appended in that arena before the two-ended RLE pass.
Nested decoders use nonoverlapping arena regions, and inputs exceeding the fixed
workspace fail before writing. Sequential recursion is limited to 64 nested
levels so malformed inputs cannot exhaust the call stack. Interleaved recursive
arrays decode as many as 63 entropy sources, then rebuild their output from
bounded index, interval-width, and dual-ended variable-bit streams. The tANS
decoder uses a bounded scalar lookup table and two-ended bit cursors.

The Huffman decoder uses a portable scalar canonical-code table and bounds-checked
bit readers. It supports sparse symbol lists and dense alternating symbol runs,
including gamma-coded run lengths and adaptive code-length deltas with all four
forced-bit widths. Code lengths through 11 bits are supported. It validates
complete tables, duplicate symbols, run bounds, stream splits, and stream
consumption. The newer format decodes unary Golomb-Rice quotients, separated
remainder bits, adaptive length residuals, truncated-binary metadata, and compact
symbol ranges with the same bounded cursor. The scalar implementation is the
correctness baseline; platform-specific acceleration can be considered after
the remaining entropy codecs are ported and benchmarked.

Whole-match distances may exceed LZB16's 16-bit window. `OozDecoder`,
`decompress`, and `decompressInto` accept `historyCapacity` in bytes
(default/minimum 65,536). Increase it before decoding streams requiring a larger
window. A reference before stream start is malformed; a valid reference beyond
the retained window throws `UnsupportedOperationException` with the required
distance. History never grows automatically. Distances are parsed as `Long` with
overflow checks; capacities are limited to `Int` arrays.

Keep codecs separate from framing, archives, and I/O adapters. Follow familiar
Kotlin I/O conventions without importing kotlinx-io or recreating its types.
Full project API guidelines are recorded in [AGENTS.md](AGENTS.md).

## Verification

```sh
./gradlew decoderChecks compileKotlinLinuxArm64 compileKotlinMacosArm64
# On an ARM64 Mac with full Xcode installed and selected:
./gradlew runDecoderChecksDebugExecutableMacosArm64
```

The same dependency-free regression checks run on JVM and macOS ARM64. They cover
fragmented input/output, block and quantum boundaries, mixed fill/raw quanta,
array ranges, trailing input, truncated and invalid headers, unsupported features,
LZB16 command forms, overlap expansion, history wraparound/restarts, whole-match
distance encodings, overflow, capacity limits, byte-array header variants, RLE
command forms, legacy sparse/dense Huffman tables and stream layouts, 128 KiB
chunk boundaries, Golomb-Rice tables, sparse symbol-range maps, and decoder
failure state. Packed-RLE checks cover nested raw, RLE, Huffman, and Huffman6
arrays plus workspace exhaustion. Recursive checks cover one/two child arrays,
nested concatenation, direct and interleaved multi-arrays, separate and combined
interval metadata, malformed streams, use inside packed RLE, exact input/output
accounting, and the depth limit. tANS checks cover legacy and Golomb-Rice table
construction, symbol ranges, its five interleaved states, recursive nesting,
truncation, and all three shared large-quantum framings. Kraken checks cover
ordinary/delta literals, recent/explicit offsets, overlapping matches, and both
inline and variable-bit extended lengths. `check`
also runs the JVM checks. No JUnit or other test dependencies are required.
Native executable linking requires full Xcode; standalone Command Line Tools
can compile the library but are insufficient for this native check executable.

## Source layout

- `commonMain`: public API and, eventually, all decoding algorithms.
- `jvmMain`: internal memory access using JDK byte-array view VarHandles.
- `nativeMain`: shared ARM64 memory access using Kotlin/Native `getIntAt`.
- Targets: JVM, Linux ARM64, macOS ARM64.

The first memory primitive is a bounds-checked, unaligned 32-bit little-endian
load. Native experimental APIs are opted into only in the implementation file.
No cinterop, pinning, manual allocation, or macOS-specific implementation is
needed for this primitive. Extend the small internal boundary as the port needs
it; benchmark before adding unsafe memory or SIMD. LZ overlapping match copies
use explicit forward-expansion semantics, not a generic bulk-copy shortcut.

The framing behavior follows `src/ooz/mod.rs` in the MIT-licensed oozextract
reference: `parse_header`, `parse_quantum_header`, `parse_whole_match`,
`read_sync`, and the raw/fill/match branches of `extract_block`. LZB16 follows `src/algorithm/lzb16.rs` with a bounded
history ring in place of whole-output indexing. During this port, the local
`lzb16-mixed` (300,000 bytes) and `lzb16-short` (777 bytes) fixtures were decoded
and compared byte-for-byte against the Rust repository's `verify` files.
Whole matches expand forward on overlap, consistent with
[`Kraken_CopyWholeMatch` in the original ooz implementation](https://github.com/powzix/ooz/blob/master/kraken.cpp#L3760).
This intentionally differs from the Rust branch's snapshot-style `copy_within`,
which can read not-yet-produced output when a whole match overlaps. No C++ code
was copied. Whole-match checks use constructed vectors; no whole-match fixtures
were available in the Rust tests inspected.

The shared byte-array layer follows `decode_bytes`, `decode_rle`, and
`decode_rle_unpacked` in `src/decoder/mod.rs`. The large-quantum adapter follows
the raw and byte-array branches of `decode_quantum`. Kraken command processing
follows `KrakenLzTable`, including the traditional two-ended offset/length bit
stream and forward-expanding match copies. Scaled offsets, excess-byte streams,
and the Mermaid/Leviathan command processors remain deferred. Tests for these
paths include constructed command vectors. All Kraken files in the inspected
local corpus—including restart and cross-block history fixtures—also decoded
byte-for-byte to their reference outputs. Mermaid and Leviathan remain covered
only at their shared framing and entropy-array boundary.

Legacy Huffman behavior follows `decode_bytes_type12`,
`huff_read_code_lengths_old`, and the scalar semantics of `HuffReader`. During
this port, the local `single-symbol-huffman.kraken` fixture decoded all 100 bytes
and matched its reference output. Multi-symbol checks use constructed canonical
tables because no matching standalone fixture was present in the inspected test
data.

New Huffman behavior follows `huff_read_code_lengths_new`,
`decode_golomb_rice_lengths`, `decode_golomb_rice_bits`, and
`convert_to_ranges`. The port expresses their optimized table operations as
bounds-checked scalar bit parsing. Constructed checks cover all forced-bit widths,
initial and internal symbol gaps, one and 256-symbol alphabets, and both output
stream layouts.

tANS behavior follows `decode_tans`, both branches of
`TansDecoder::decode_table`, and `TansDecoder::init_lut`. State transitions use
portable bounded cursors over the forward and backward bitstreams. New table
metadata reuses the same bounded Golomb-Rice and symbol-range semantics as the
Huffman implementation.

Packed RLE behavior follows the scratch-buffer branch of `decode_rle`: a leading
byte array is decoded into bounded workspace, remaining command bytes are
appended, and `decode_rle_unpacked` consumes literals from the front and commands
from the back. The workspace is owned and reused by `OozDecoder`; direct internal
byte-array decoding creates one only when a packed RLE path needs it.

Sequential recursive behavior follows the noninterleaved branch of
`decode_recursive`: the control byte permits at most two child arrays, each child
uses the same byte-array decoder, and decoded results are concatenated into the
exact parent output range. The high-bit form follows `decode_multi_array`: it
decodes entropy arrays into bounded workspace and interleaves intervals into the
exact parent output range.

The checked-in regression suite uses self-contained constructed vectors and
does not require that sibling repository.

Toolchain and API references:
[KMP compatibility](https://kotlinlang.org/docs/multiplatform/multiplatform-compatibility-guide.html),
[Native getIntAt](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.native/get-int-at.html).
