#include <sodium.h>
#include <stdio.h>
#include <string.h>

// This code is extracted from libsodium to allow setting the nonce manually
#define crypto_secretstream_xchacha20poly1305_COUNTERBYTES 4U
#define crypto_secretstream_xchacha20poly1305_INONCEBYTES 8U

#define STATE_COUNTER(STATE) ((STATE)->nonce)
#define STATE_INONCE(STATE)                                                    \
  ((STATE)->nonce + crypto_secretstream_xchacha20poly1305_COUNTERBYTES)

void _crypto_secretstream_xchacha20poly1305_counter_reset(
    crypto_secretstream_xchacha20poly1305_state *state) {
  memset(STATE_COUNTER(state), 0,
         crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  STATE_COUNTER(state)[0] = 1;
}

int crypto_secretstream_xchacha20poly1305_init_push_patched(
    crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char out[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
  crypto_core_hchacha20(state->k, out, k, NULL);
  _crypto_secretstream_xchacha20poly1305_counter_reset(state);
  memcpy(STATE_INONCE(state), out + crypto_core_hchacha20_INPUTBYTES,
         crypto_secretstream_xchacha20poly1305_INONCEBYTES);
  memset(state->_pad, 0, sizeof state->_pad);

  return 0;
}

void print_array(const char *text, const unsigned char *ar, unsigned len) {
  printf("%s[", text);
  for (unsigned i = 0; i < len; i++) {
    printf("%iu8, ", ar[i]);
  }
  printf("];\n");
}

void print_test_case_begin(const char *test_case_name)
{
  printf("#[test]\n");
  printf("fn %s() {\n", test_case_name);
}

void print_test_case_end()
{
  printf("}\n");
}

void print_test_case_comment(const char *comment)
{
  printf("# %s\n", comment);
}

void print_internal_state(crypto_secretstream_xchacha20poly1305_state *state, const char *text)
{
  if (strcmp(text, "before") == 0)
  {  
    print_array("let before_internal_key: [u8; 32] = ", state->k, 32);
    print_array("let before_internal_nonce: [u8; 12] = ", state->nonce, 12);
    print_array("let before_internal_counter: [u8; 4] = ", STATE_COUNTER(state), crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  }

  if (strcmp(text, "after") == 0)
  {  
    print_array("let after_internal_key: [u8; 32] = ", state->k, 32);
    print_array("let after_internal_nonce: [u8; 12] = ", state->nonce, 12);
    print_array("let after_internal_counter: [u8; 4] = ", STATE_COUNTER(state), crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  }
}

const unsigned char default_msg[] = "Default message to test streaming AEAD encryption.";

void ctx_msg_to_final(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_new_to_msg_with_tag_final");

  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));

  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_final());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_msg_to_final_double(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_new_to_msg_with_tag_final_twice");

  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));

  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_final());
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_final());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_msg_to_rekey(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_new_to_msg_with_tag_rekey");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));
  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_rekey());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_msg_to_rekey_double(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_new_to_msg_with_tag_rekey_twice");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));

  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_rekey());
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_rekey());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_msg_to_push(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_new_to_msg_with_tag_push");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));

  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_push());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_msg_counter_overflow(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_counter_overflow_with_tag_msg");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  memset(STATE_COUNTER(&st), 0xFFFFFFFF,
         crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));
  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_rekey_counter_overflow(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_counter_overflow_with_tag_rekey");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  memset(STATE_COUNTER(&st), 0xFFFFFFFF,
         crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));
  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_rekey());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_final_counter_overflow(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_counter_overflow_with_tag_final");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  memset(STATE_COUNTER(&st), 0xFFFFFFFF,
         crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));
  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_final());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void ctx_push_counter_overflow(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_counter_overflow_with_tag_push");
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);
  memset(STATE_COUNTER(&st), 0xFFFFFFFF,
         crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
  print_internal_state(&st, "before");
  print_array("let input = ", default_msg, sizeof(default_msg));
  
  unsigned char cipher[100];
  unsigned long long clen_out;
  
  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, default_msg, sizeof(default_msg), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_push());
  
  print_internal_state(&st, "after");
  print_array("let out = ", cipher, clen_out);
  print_test_case_end();
}

void stream_with_explicit_rekey(unsigned char *header, const unsigned char *key)
{
  print_test_case_begin("test_seal_open_with_explicit_rekey");
  
  /// Encryptes 5 messages. Rekey is forced after three 
  unsigned char msg1[] = "test1";
  unsigned char msg2[] = "this is longer text";
  unsigned char msg3[] = "1";
  unsigned char msg4[] = "first text after rekey";
  unsigned char msg5[] = "this is the second text after rekey";
  
  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);

  print_array("1st Message: ", msg1, sizeof(msg1));
  print_array("2nd Message: ", msg2, sizeof(msg2));
  print_array("3rd Message: ", msg3, sizeof(msg3));
  print_array("4th Message: ", msg4, sizeof(msg4));
  print_array("5th Message: ", msg5, sizeof(msg5));

  print_internal_state(&st, "before");

  unsigned char cipher[100];
  unsigned long long clen_out;

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg1, sizeof(msg1), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg1:\n");
  print_internal_state(&st, "after");
  print_array("Ciphertext: ", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg2, sizeof(msg2), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg2:\n");
  print_internal_state(&st, "after");
  print_array("Ciphertext: ", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg3, sizeof(msg3), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg3:\n");
  print_internal_state(&st, "after");
  print_array("Ciphertext: ", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_rekey(&st);
  printf("After Rekey:\n");
  print_internal_state(&st, "after");

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg4, sizeof(msg4), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg4:\n");
  print_internal_state(&st, "after");
  print_array("Ciphertext: ", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg5, sizeof(msg5), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg5:\n");
  print_internal_state(&st, "after");
  print_array("Ciphertext: ", cipher, clen_out);
  print_test_case_end();
}

int main() {

  if (sodium_init() == -1)
  {
    printf("[FATAL]: libsodium could not be initialized.");
    return 1;
  }

  char key_str[] = "123456789abcdefghijklmonpqrstuv";
  char header_str[] = "abababababababababaabab";

  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  memcpy(key, key_str, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  memcpy(header, header_str, crypto_secretstream_xchacha20poly1305_HEADERBYTES);

  print_array("SK: ", key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  print_array("NONCE: ", header, crypto_secretstream_xchacha20poly1305_HEADERBYTES);

  ctx_msg_to_final(header, key);
  ctx_msg_to_rekey(header, key);
  ctx_msg_to_final_double(header, key);
  ctx_msg_to_rekey_double(header, key);
  ctx_msg_to_push(header, key);
  ctx_msg_counter_overflow(header, key);
  ctx_rekey_counter_overflow(header, key);
  ctx_final_counter_overflow(header, key);
  ctx_push_counter_overflow(header, key);
  stream_with_explicit_rekey(header, key);

  return 0;
}