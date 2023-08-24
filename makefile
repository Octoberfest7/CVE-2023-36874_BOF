all:
	x86_64-w64-mingw32-g++ -o dist/wer_lpe.x64.o -Os -c src/main.cpp -lole32 -loleaut32 -Wno-write-strings -Wno-attributes
