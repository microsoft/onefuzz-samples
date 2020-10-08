all:
	go get github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build -libfuzzer -o example.a .
	clang -fsanitize=fuzzer example.a -o fuzz.exe

clean:
	rm -f example.a fuzz.exe
