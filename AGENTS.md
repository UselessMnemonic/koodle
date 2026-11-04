# Public API design

Use `com.uselessmnemonic` as the base package. The library must have no external
dependencies beyond the Kotlin standard library and platform APIs. Kompressor,
KorIO, kotlinx-io, Okio, and Apache Commons Compress are design inspiration,
not dependencies.

- Define small capability interfaces. Use top-level functions and extensions for
  conveniences. Avoid unnecessary inheritance, factories, and abstraction layers.
- Separate algorithms from I/O. Do not couple decoding to memory, files, streams,
  or seeking. Do not recreate a general-purpose I/O framework or vendor copies of
  `RawSource`, `RawSink`, or `Buffer`. The zero-dependency requirement takes
  precedence over the preference for kotlinx-io abstractions.
- Design the codec core for incremental processing and bounded working memory.
  Whole-array operations should be eager conveniences over that same core, not
  a separate implementation. Do not require whole inputs or outputs in memory.
- Keep codecs, framing formats, and archives separate and composable.
- Model only supported capabilities: decoding does not imply encoding, reading
  an archive does not imply writing, and reading input does not imply seeking.
- Use strongly typed constructors, properties, and format-specific options.
  Avoid generic maps, string-based settings, and universal configuration objects.
- Make resource ownership and failure behavior explicit. State who opens and
  closes resources; use structured resource management where resources exist.
  Do not add resource lifecycles to objects that do not need them.
- Keep public contracts portable. Isolate JVM/native APIs in platform source
  sets and keep Java-specific types out of common APIs.
- Provide straightforward ByteArray conveniences and, when implemented,
  buffer/file adapters that delegate to the same decoding core.
- Prefer consistent names and familiar Kotlin conventions. Avoid unnecessary
  DSLs, implicit global state, and excessive operator overloading.

Keep the core minimal and composable while making common operations effortless.
Public APIs should express caller intent, not compression implementation details.
The incremental Decoder capability and OozDecoder framing implementation form
the current core. Eager top-level conveniences delegate to that core. Keep codec
implementations separate from framing as they are introduced.
