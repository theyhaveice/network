CXX = clang++
CXXFLAGS = -std=c++11 -framework Foundation -framework CoreServices
TARGET = network
SRCS = network.mm main.cpp

build:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
