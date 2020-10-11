all:
	g++ -c -g -std=c++14 -o objs/graph.o graph.cpp
	g++ -c -g -std=c++14 -o objs/helper.o helper.cpp
	g++ -c -g -std=c++14 -o objs/test_main.o test_main.cpp
	g++ -dynamiclib objs/helper.o objs/graph.o -o libhelper.dylib
	g++ objs/helper.o objs/graph.o objs/test_main.o -o bin/test_main
	mv libhelper.dylib ../libs/libhelper.dylib
clean:
	rm graph.o helper.o libhelper.dylib test_main test_main.o
