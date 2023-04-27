#include <ctype.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>
#define NBITS 512

/*header*/
void string2hexString(char *input, char *output);
void hexString2string(char *input, char *output);
BIGNUM *encryption(char *message, BIGNUM *e, BIGNUM *n, BN_CTX *ctx);
char *decryption(BIGNUM *bn_cipher, BIGNUM *d, BIGNUM *n, BN_CTX *ctx);
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void printBN(char *msg, BIGNUM *a);

/*
 * define RSA structure
 * one is constant ONE in BIGNUM
 * ctx to save malloc space for BIGNUM
 * p,q is random selected BIGNUM
 * n = p*q
 * phiN=(p-1)(q-1);
 * gcd(e,phiN)=1 && 1<e<phiN;
 * d is e^-1 on phiN
 */
typedef struct {
  BIGNUM *ONE; // constant ONE
  BN_CTX *ctx; // to save malloc space for BIGNUM
  BIGNUM *p, *q, *pSubOne, *qSubOne, *n, *phiN, *e, *d;
} Rsa;

/*
 * all necessary element be initialized in RSA
 */

Rsa *create_RSA() {
  Rsa *rsa = (Rsa *)malloc(sizeof(Rsa));
  
  rsa->ctx= BN_CTX_new();
  rsa->ONE = BN_new(); // constant ONE
  BN_one(rsa->ONE);    // initial the constant BIGNUM ONE

  rsa->p = BN_new();       // random large prime number
  rsa->q = BN_new();       // random large prime number
  rsa->pSubOne = BN_new(); // p-1
  rsa->qSubOne = BN_new(); // q-1
  rsa->n = BN_new();       // p*q
  rsa->phiN = BN_new();    //(p-1)*(q-1)
  rsa->e = BN_new();       // gcd(e,phiN)=1 && 1<e<phiN
  rsa->d = BN_new();       // contain private key by calculated

  // initial all value by random p and radom q
  BN_generate_prime_ex(rsa->p, NBITS, 1, NULL, NULL, NULL);
  BN_generate_prime_ex(rsa->q, NBITS, 1, NULL, NULL, NULL);

  BN_sub(rsa->pSubOne, rsa->p, rsa->ONE);
  BN_sub(rsa->qSubOne, rsa->q, rsa->ONE);
  BN_mul(rsa->n, rsa->p, rsa->q, rsa->ctx);
  BN_mul(rsa->phiN, rsa->pSubOne, rsa->qSubOne, rsa->ctx);

  // random select e
  do{
    BN_rand_range(rsa->e,rsa->phiN);
  }while (!BN_are_coprime(rsa->e, rsa->phiN, rsa->ctx));
  // calculate the private key d by given mod inverse
  BN_mod_inverse(rsa->d, rsa->e, rsa->phiN, rsa->ctx);
  return rsa;
}

/*
 * function that converts ascii string to hex string
 * the very first step of encryption
 */
void string2hexString(char *input, char *output) {
  int loop = 0, i = 0;

  while (input[loop] != '\0') {
    sprintf((char *)(output + i), "%02X", input[loop]);
    loop += 1;
    i += 2;
  }
  // insert NULL at the end of the output string
  output[i++] = '\0';
}

/*
 * function that converts hex string back to ascii string
 * the last step of decryption
 */
void hexString2string(char *input, char *output) {
  int i = 0, o = 0;
  while (input[i] != '\0') {
    // use isalpha to convert upper letter approach to 9 since C do not have
    // strol() function
    if (isalpha(input[i]))
      input[i] -= 7;
    if (isalpha(input[i + 1]))
      input[i + 1] -= 7;
    // get the ascii num for each char
    int ascii_num = (int)(input[i] - '0') * 16 + (int)(input[i + 1] - '0');
    // 8F -> (int)8 - '0', (int)F-
    sprintf((char *)(output + o), "%c", ascii_num);
    i += 2;
    o += 1;
  }
  // insert NULL at the end of the output string
  output[o++] = '\0';
}

/*
 * function encrypt plain text message to BIGNUM
 */
BIGNUM *encryption(char *message, BIGNUM *e, BIGNUM *n, BN_CTX *ctx) {
  char hex_mes[(strlen(message) * 2) + 1];
  // message to hex
  string2hexString(message, hex_mes);
  // hex message to bin
  BIGNUM *bn_mes = BN_new();
  BN_hex2bn(&bn_mes, hex_mes);

  BIGNUM *r = BN_new();
  BN_mod_exp(r, bn_mes, e, n, ctx);
  return r;
}

/*
 * function decrypt BIGNUM object to plain text message
 */
char *decryption(BIGNUM *bn_cipher, BIGNUM *d, BIGNUM *n, BN_CTX *ctx) {
  BIGNUM *r = BN_new();
  BN_mod_exp(r, bn_cipher, d, n, ctx); // r is the message in binary form

  // bin message to hex message
  char *hex_message = BN_bn2hex(r);
  // hex message to plain message
  char *decrypted_mes = malloc(sizeof(char) * strlen(hex_message));
  hexString2string(hex_message, decrypted_mes);

  return decrypted_mes;
}

/* reference: https://github.com/openssl/openssl/blob/master/crypto/bn/bn_gcd.c The numbers
 * a and b are coprime if the only positive integer that is a divisor of both of
 * them is 1. i.e. gcd(a,b) = 1.
 *
 * Coprimes have the property: b has a multiplicative inverse modulo a
 * i.e there is some value x such that bx = 1 (mod a).
 *
 * Testing the modulo inverse is currently much faster than the constant
 * time version of BN_gcd().
 */
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
  int ret = 0;
  BIGNUM *tmp;

  BN_CTX_start(ctx);
  tmp = BN_CTX_get(ctx);
  if (tmp == NULL)
    goto end;
  BN_set_flags(a, BN_FLG_CONSTTIME);
  ret = (BN_mod_inverse(tmp, a, b, ctx) != NULL);
end:
  BN_CTX_end(ctx);
  return ret;
}

/* reference: https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_RSA/Crypto_RSA.pdf
 * help function
 * print the BINNUM to hex string with message
 */
void printBN(char *msg, BIGNUM *a) {
  /* Use BN_bn2hex(a) for hex string
   * Use BN_bn2dec(a) for decimal string */
  char *number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

int main() {

  // start the process
  char message[NBITS / 2 + 1];
  printf("Enter your message: ");
  scanf("%512[^\n]", message);

  //create rsa
  Rsa *rsa = create_RSA();

  // plain message to bin cipher
  BIGNUM *bn_cipher = encryption(message, rsa->e, rsa->n, rsa->ctx);

  // bin cipher to plain message
  char *decrypted_mes;
  decrypted_mes = decryption(bn_cipher, rsa->d, rsa->n, rsa->ctx);

  // print p and q
  printBN("The random p generated is: ", rsa->p);
  printBN("The random q generated is: ", rsa->q);
  printBN("The e be selected is: ", rsa->e);

  // print private key
  printBN("By module inverse private key d is: ", rsa->d);

  printBN("The cipher Text is: ", bn_cipher);

  printf("The message is: '%s'\n", decrypted_mes);

  return 0;
}