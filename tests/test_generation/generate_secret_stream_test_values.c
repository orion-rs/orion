#include <sodium.h>
#include <stdio.h>
#include <string.h>

// This code is extracted form libsodium to allow setting the nonce manually
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
  printf("%s: [", text);
  for (unsigned i = 0; i < len; i++) {
    printf("%iu8, ", ar[i]);
  }
  printf("]\n");
}

int main() {
  /// Encryptes 5 messages. Rekey is forced after three
  char key_str[] = "123456789abcdefghijklmonpqrstuv";
  char header_str[] = "abababababababababaabab";
  unsigned char msg1[] = "test1";
  unsigned char msg2[] = "this is longer text";
  unsigned char msg3[] = "1";
  unsigned char msg4[] = "first text after rekey";
  unsigned char msg5[] = "this is the second text after rekey";

  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  // sodium_memzero(key, 32);
  memcpy(key, key_str, crypto_secretstream_xchacha20poly1305_KEYBYTES);
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  memcpy(header, header_str, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  // sodium_memzero(key, 24);

  crypto_secretstream_xchacha20poly1305_state st;
  crypto_secretstream_xchacha20poly1305_init_push_patched(&st, header, key);

  print_array("key", key, crypto_secretstream_xchacha20poly1305_KEYBYTES);

  print_array("nonce", header,
              crypto_secretstream_xchacha20poly1305_HEADERBYTES);

  print_array("msg1", msg1, sizeof(msg1));
  print_array("msg2", msg2, sizeof(msg2));
  print_array("msg3", msg3, sizeof(msg3));
  print_array("msg4", msg4, sizeof(msg4));
  print_array("msg5", msg5, sizeof(msg5));

  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);

  unsigned char cipher[100];
  unsigned long long clen_out;

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg1, sizeof(msg1), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg1:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);
  print_array("cipher text", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg2, sizeof(msg2), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg2:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);
  print_array("cipher text", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg3, sizeof(msg3), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg3:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);
  print_array("cipher text", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_rekey(&st);
  printf("After Rekey:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg4, sizeof(msg4), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg4:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);
  print_array("cipher text", cipher, clen_out);

  crypto_secretstream_xchacha20poly1305_push(
      &st, cipher, &clen_out, msg5, sizeof(msg5), NULL, 0,
      crypto_secretstream_xchacha20poly1305_tag_message());
  printf("After Msg5:\n");
  print_array("Internal key", st.k, 32);
  print_array("Internal nonce", st.nonce, 12);
  print_array("cipher text", cipher, clen_out);
  return 0;
}
