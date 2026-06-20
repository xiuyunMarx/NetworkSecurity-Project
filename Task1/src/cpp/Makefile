CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp -lcrypto

PROGRAMS := keygen rsa_enc rsa_dec

.PHONY: all clean

all: $(PROGRAMS)

keygen: keygen.cpp rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

rsa_enc: rsa_enc.cpp rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

rsa_dec: rsa_dec.cpp rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGRAMS)
