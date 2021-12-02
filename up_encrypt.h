#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef struct PKey PubPKey;
typedef struct RustEmail Email;

#define SUCCESS 0

#define NULL_ERROR -1

#define NOT_VERIFY -2

#define UTF8_ERROR -3

#define EMAIL_PARSE_ERROR -4

#define STRING_CONVERT_ERROR -5

int32_t get_email(const uint8_t *input, uintptr_t input_len, Email **email);

void print_email(const Email *email);

void drop_email(Email *email);

int32_t verify_dkim_signature(const Email *email, uint32_t e, const uint8_t *n, uintptr_t n_len);

int32_t get_header_value(const Email *email,
                         const uint8_t *header,
                         uintptr_t header_len,
                         uint8_t **res,
                         uintptr_t *res_len);

int32_t get_body(const Email *email, uint8_t **res, uintptr_t *res_len);

int32_t print_pub_pkey(const PubPKey *input);

void drop_pub_pkey(PubPKey *input);

int32_t pub_pkey_from_component(uint32_t e,
                                const uint8_t *n,
                                uintptr_t n_len,
                                PubPKey **pub_pkey_res);

int32_t pub_pkey_verify(const PubPKey *pub_pkey,
                        const uint8_t *message,
                        uintptr_t message_len,
                        const uint8_t *signature,
                        uintptr_t signature_len);

int32_t sha256(const uint8_t *input,
               uintptr_t input_len,
               const uint8_t **output,
               uintptr_t *output_len);
