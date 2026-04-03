#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

void hash_password(const char* password, const char* salt, char* output) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    char combined[256];
    
    snprintf(combined, sizeof(combined), "%s%s", salt, password);
    
    crypto_hash_sha256(hash, (unsigned char*)combined, strlen(combined));
    
    for (int i = 0; i < crypto_hash_sha256_BYTES; i++) {
        sprintf(output + i*2, "%02x", hash[i]);
    }
    output[64] = '\0';
}

void brute(const char* alph, int alph_len, int n, char* current, int pos,
           const char* target_hash, const char* salt) {
    if (pos == n) {
        current[n] = '\0';
        char hash_str[65];
        hash_password(current, salt, hash_str);
        if (strcmp(hash_str, target_hash) == 0) {
            printf("%s\n", current);
            exit(0);
        }
        return;
    }
    for (int i = 0; i < alph_len; i++) {
        current[pos] = alph[i];
        brute(alph, alph_len, n, current, pos + 1, target_hash, salt);
    }
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    
    int opt;
    char* alphabet = NULL;
    char* hash = NULL;
    char* salt = NULL;
    int n = 0;
    
    while ((opt = getopt(argc, argv, "a:n:h:s:")) != -1) {
        switch(opt) {
            case 'a': alphabet = optarg; break;
            case 'n': n = atoi(optarg); break;
            case 'h': hash = optarg; break;
            case 's': salt = optarg; break;
            default:
                fprintf(stderr, "Usage: %s -a alphabet -n length -h hash -s salt\n", argv[0]);
                return 1;
        }
    }
    
    if (!alphabet || n <= 0 || !hash || !salt) {
        fprintf(stderr, "Missing arguments\n");
        return 1;
    }
    
    int alph_len = strlen(alphabet);
    char current[n + 1];
    brute(alphabet, alph_len, n, current, 0, hash, salt);
    fprintf(stderr, "Hash not found\n");
    return 1;
}