all:
	g++ -c -g -std=c++14 -o graph.o graph.cpp
	g++ -c -g -std=c++14 -o helper.o helper.cpp
	g++ -c -g -std=c++14 -o test_main.o test_main.cpp
	g++ -dynamiclib helper.o graph.o -o libhelper.dylib
	g++ helper.o graph.o test_main.o -o test_main
	cp libhelper.dylib ../libs/libhelper.dylib
clean:
	rm graph.o helper.o libhelper.dylib test_main test_main.o
	