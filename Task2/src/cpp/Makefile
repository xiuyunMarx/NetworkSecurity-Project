CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp -lcrypto

all: wup_cca2

wup_cca2: wup_cca2.cpp ../../../Task1/src/cpp/rsa_utils.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f wup_cca2 ../../History_Message.txt ../../AES_Key.txt \
		../../WUP_Request.txt ../../AES_Encrypted_WUP.txt ../../attack_log.txt
