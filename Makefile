CXX      := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wpedantic -Iinclude
POLICY   := policies/enterprise_example.json

.PHONY: all policy build test verify clean

all: policy build test

policy:
	python3 tools/policy_compiler.py $(POLICY) include/generated_policy.hpp lean/generated_policy_cert.lean

build: policy
	$(CXX) $(CXXFLAGS) -o mcp-dfa-gate src/mcp_sidecar.cpp

test: build
	python3 tests/test_sidecar.py

verify: policy
	lean lean/lattice_proof.lean

clean:
	rm -f mcp-dfa-gate
