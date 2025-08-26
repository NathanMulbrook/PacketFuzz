/*
 * Scapy LibFuzzer C Extension
 * 
 * Provides high-performance mutation functions using libFuzzer's algorithms.
 * This module exports functions that can be called from Python to perform
 * mutations on byte data.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// libFuzzer function declarations
// These are provided by libFuzzer when linking
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
extern size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);

// LibFuzzer dictionary support functions (always available)
extern void __libfuzzer_add_word(const uint8_t *Data, size_t Size);

// Dictionary storage for hybrid approach
static uint8_t **g_loaded_dictionaries = NULL;
static size_t *g_dict_sizes = NULL;
static size_t g_dict_count = 0;

// Internal state
static int initialized = 0;
static unsigned int global_seed = 0;

/*
 * Initialize the fuzzer with an optional seed
 */
int init_libfuzzer(unsigned int seed) {
    if (seed == 0) {
        seed = (unsigned int)time(NULL);
    }
    global_seed = seed;
    srand(seed);
    initialized = 1;
    return 0;
}

/*
 * Load dictionaries for native LibFuzzer support
 * This enables LibFuzzer to use dictionary entries as corpus seeds and for crossover
 */
int load_dictionaries_native(const char **dictionary, size_t dict_count) {
    if (!initialized) {
        init_libfuzzer(0);
    }
    // Free existing dictionaries
    if (g_loaded_dictionaries) {
        for (size_t i = 0; i < g_dict_count; i++) {
            free(g_loaded_dictionaries[i]);
        }
        free(g_loaded_dictionaries);
        free(g_dict_sizes);
        g_loaded_dictionaries = NULL;
        g_dict_sizes = NULL;
        g_dict_count = 0;
    }
    if (dict_count == 0 || dictionary == NULL) {
        return 0;
    }
    // Allocate storage for dictionaries
    g_loaded_dictionaries = malloc(dict_count * sizeof(uint8_t*));
    g_dict_sizes = malloc(dict_count * sizeof(size_t));
    if (!g_loaded_dictionaries || !g_dict_sizes) {
        if (g_loaded_dictionaries) free(g_loaded_dictionaries);
        if (g_dict_sizes) free(g_dict_sizes);
        g_loaded_dictionaries = NULL;
        g_dict_sizes = NULL;
        return -1;
    }
    // Load dictionaries
    for (size_t i = 0; i < dict_count; i++) {
        size_t len = strlen(dictionary[i]);
        if (len == 0) continue;
        g_loaded_dictionaries[i] = malloc(len);
        if (!g_loaded_dictionaries[i]) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                free(g_loaded_dictionaries[j]);
            }
            free(g_loaded_dictionaries);
            free(g_dict_sizes);
            g_loaded_dictionaries = NULL;
            g_dict_sizes = NULL;
            return -1;
        }
        memcpy(g_loaded_dictionaries[i], dictionary[i], len);
        g_dict_sizes[i] = len;
        // Add to LibFuzzer's native dictionary
        __libfuzzer_add_word(g_loaded_dictionaries[i], len);
    }
    g_dict_count = dict_count;
    return 1;  // Return 1 indicating success
}

/*
 * Enhanced dictionary-based mutation with hybrid approach
 * Uses LibFuzzer native dictionary support when available, falls back to custom logic
 */
size_t mutate_with_dict_enhanced(const uint8_t *input_data, size_t input_size,
                                uint8_t *output_data, size_t max_output_size,
                                const char **dictionary, size_t dict_size,
                                unsigned int seed) {
    if (!initialized) {
        init_libfuzzer(seed);
    }
    if (input_size == 0 || max_output_size == 0) {
        return 0;
    }
    // Copy input to output buffer
    size_t copy_size = input_size > max_output_size ? max_output_size : input_size;
    memcpy(output_data, input_data, copy_size);
    // If dictionaries are loaded, use LibFuzzer's native dictionary support
    if (g_dict_count > 0) {
        size_t result_size = LLVMFuzzerMutate(output_data, copy_size, max_output_size);
        if (result_size != copy_size || memcmp(input_data, output_data, copy_size) != 0) {
            return result_size;
        }
        if (LLVMFuzzerCustomMutator != NULL) {
            result_size = LLVMFuzzerCustomMutator(output_data, copy_size, max_output_size, seed);
            if (result_size != copy_size) {
                return result_size;
            }
        }
    }
    return LLVMFuzzerMutate(output_data, copy_size, max_output_size);
}
