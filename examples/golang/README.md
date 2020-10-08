# Fuzzing Golang in OneFuzz

OneFuzz can orchastrate fuzzing of GoLang using
[go-fuzz](https://github.com/dvyukov/go-fuzz) in `libfuzzer` mode.

Included in this directory is a simple example to demonstrate golang based
fuzzing.  For more examples, check out the collection of [go-fuzz
examples](https://github.com/dvyukov/go-fuzz-corpus).

## Example command

```bash
make
onefuzz template libfuzzer basic golang-sample basic-example build-1 linux --target_exe ./fuzz.exe --inputs ./seeds
```

NOTE: This assumes a [pool](https://github.com/microsoft/onefuzz/blob/main/docs/terminology.md#pool) named `linux`.
