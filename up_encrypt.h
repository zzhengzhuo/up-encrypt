#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SUCCESS 0

#define NULL_ERROR -1

#define NOT_VERIFY -2

#define UTF8_ERROR -3

#define EMAIL_PARSE_ERROR -4

#define STRING_CONVERT_ERROR -5

int32_t email_verify(const uint8_t *email_s,
                     uintptr_t email_s_len,
                     uint32_t e,
                     const uint8_t *n,
                     uintptr_t n_len,
                     uint8_t **subject,
                     uintptr_t *subject_len,
                     uint8_t **from,
                     uintptr_t *from_len);

int32_t rsa_with_sha256_verify(uint32_t e,
                               const uint8_t *n,
                               uintptr_t n_len,
                               const uint8_t *message,
                               uintptr_t message_len,
                               const uint8_t *signature,
                               uintptr_t signature_len);

int32_t sha256(const uint8_t *input,
               uintptr_t input_len,
               const uint8_t **output,
               uintptr_t *output_len);
