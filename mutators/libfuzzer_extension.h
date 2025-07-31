/*
 * Scapy LibFuzzer C Extension Header
 * 
 * Function declarations for the libFuzzer integration module
 */

#ifndef SCAPY_LIBFUZZER_H
#define SCAPY_LIBFUZZER_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the fuzzer with an optional seed
 * Returns 0 on success
 */
int init_libfuzzer(unsigned int seed);

/*
 * Load dictionaries for LibFuzzer
 * Returns 1 on success, 0 if no dictionaries loaded, -1 on error
 */
int load_dictionaries_native(const char **dictionary, size_t dict_count);

/*
 * Enhanced dictionary-based mutation with hybrid approach
 * Uses LibFuzzer native dictionary support when available
 * 
 * Returns: Size of mutated data, 0 on error
 */
size_t mutate_with_dict_enhanced(const uint8_t *input_data, size_t input_size,
                                uint8_t *output_data, size_t max_output_size,
                                const char **dictionary, size_t dict_size,
                                unsigned int seed);

/*
 * Generate initial seed from dictionary for corpus
 * 
 * Returns: Size of generated seed, 0 on error
 */
size_t generate_dict_seed(uint8_t *output_data, size_t max_output_size,
                         const char **dictionary, size_t dict_size,
                         unsigned int seed);

/*
 * Utility functions
 */
void get_random_bytes(uint8_t *buffer, size_t size);

size_t simple_mutate(uint8_t *data, size_t size, size_t max_size);

#ifdef __cplusplus
}
#endif

#endif /* SCAPY_LIBFUZZER_H */
