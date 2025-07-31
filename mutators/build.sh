#!/bin/bash

# Minimal build script for Scapy LibFuzzer C Extension (Linux only)
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MUTATORS_DIR="$PROJECT_ROOT/mutators"
BUILD_DIR="$PROJECT_ROOT/build"
EXTENSION_NAME="libscapy_libfuzzer.so"

# Check if clang is available
if ! command -v clang &> /dev/null; then
    echo "[ERROR] clang is required but not installed. Please install clang."
    exit 1
fi

# Check for libFuzzer support
cat > /tmp/libfuzzer_test.c << 'EOF'
#include <stdint.h>
#include <stdlib.h>
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
int main() { return 0; }
EOF
if ! clang -fsanitize=fuzzer /tmp/libfuzzer_test.c -o /tmp/libfuzzer_test 2>/dev/null; then
    echo "[ERROR] libFuzzer support is required. Please install clang with libFuzzer support."
    rm -f /tmp/libfuzzer_test.c /tmp/libfuzzer_test
    exit 1
fi
rm -f /tmp/libfuzzer_test.c /tmp/libfuzzer_test

build() {
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    clang -shared -fPIC -O2 \
        -fsanitize=fuzzer-no-link \
        -I"$MUTATORS_DIR" \
        "$MUTATORS_DIR/libfuzzer_extension.c" \
        -o "$MUTATORS_DIR/$EXTENSION_NAME"
    echo "[INFO] Built $EXTENSION_NAME with libFuzzer support."
}

clean() {
    rm -rf "$BUILD_DIR"
    rm -f "$MUTATORS_DIR"/*.so
    echo "[INFO] Clean complete."
}

test_extension() {
    cd "$PROJECT_ROOT"
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from mutators.libfuzzer_mutator import LibFuzzerMutator
    mutator = LibFuzzerMutator()
    if mutator.is_libfuzzer_available():
        print('libFuzzer extension loaded successfully')
    test_data = b'Hello, World!'
    mutated = mutator.mutate_bytes(test_data)
    print(f'Basic mutation test passed (original: {len(test_data)} bytes, mutated: {len(mutated)} bytes)')
except Exception as e:
    print(f'Test failed: {e}')
    sys.exit(1)
"
    if [ $? -eq 0 ]; then
        echo "[INFO] Extension tests passed!"
    else
        echo "[ERROR] Extension tests failed!"
        exit 1
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [command]

Commands:
  build     Build the C extension (default)
  clean     Clean build artifacts
  test      Test the compiled extension
  help      Show this help message

Requirements:
  - Linux
  - clang compiler with libFuzzer support
  - Python 3.6+
  - Scapy library
EOF
}

case "${1:-build}" in
    clean)
        clean
        ;;
    test)
        test_extension
        ;;
    help|--help|-h)
        show_usage
        ;;
    build|*)
        build
        ;;
esac
