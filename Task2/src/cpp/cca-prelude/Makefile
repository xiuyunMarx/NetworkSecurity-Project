CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp

all: cca_attack

cca_attack: cca_attack.cpp ../../../../Task1/src/cpp/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f cca_attack
