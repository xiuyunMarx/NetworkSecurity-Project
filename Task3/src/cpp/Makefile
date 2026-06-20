CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp -lcrypto

PROGRAMS := OAEP_encoding OAEP_decoding OAEP_cca2_demo

.PHONY: all clean

all: $(PROGRAMS)

OAEP_encoding: OAEP_encoding.cpp OAEP_utils.h ../../../Task1/src/cpp/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

OAEP_decoding: OAEP_decoding.cpp OAEP_utils.h ../../../Task1/src/cpp/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

OAEP_cca2_demo: OAEP_cca2_demo.cpp OAEP_utils.h ../../../Task1/src/cpp/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGRAMS) ../../Random_Number.txt \
		../../Message_After_Padding.txt ../../Encrypted_Message.txt
