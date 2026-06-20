CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDLIBS := -lgmpxx -lgmp

OUTDIR := rsa
PROGRAMS := $(OUTDIR)/keygen $(OUTDIR)/rsa_enc $(OUTDIR)/rsa_dec

.PHONY: all clean

all: $(PROGRAMS)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/keygen: keygen.cpp rsa_utils.h | $(OUTDIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(OUTDIR)/rsa_enc: rsa_enc.cpp rsa_utils.h | $(OUTDIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(OUTDIR)/rsa_dec: rsa_dec.cpp rsa_utils.h | $(OUTDIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -rf $(OUTDIR)
