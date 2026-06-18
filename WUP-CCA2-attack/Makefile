CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp -lcrypto

all: wup_cca2

wup_cca2: wup_cca2.cpp ../textbook-rsa/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f wup_cca2 history_message.txt
