#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

#define NUM_THREADS       4
#define MIN_PASSWORD_LEN  2
#define MAX_PASSWORD_LEN  4
#define ALFABETO_LEN      62

const char alfabeto[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// --- PRNG e HASH MAO-64 ---
static uint32_t ri = 0;
void hsrand(uint32_t seed) {
    ri = seed;
}
uint8_t hrand() {
    // Ponteiro de byte
    uint8_t* p = (uint8_t*)(&ri);
    // Calculando próximo número
    ri = (1103515245 * ri) + 12345;
    // Retornando byte de checksum
    return p[0] ^ p[1] ^ p[2] ^ p[3];
}
// Removido __restrict__ conforme solicitado
void MAO_64(uint8_t* hash, const char* senha, size_t len) {
    uint32_t seed = 0;
    for (size_t i = 0; i < len; i++) {
        seed = (seed << 8) | ((seed >> 24) ^ (uint8_t)senha[i]);
    }
    hsrand(seed);
    memset(hash, 0, 8);
    for (int i = 0; i < 32; i++) {
        hash[i & 7] ^= hrand();
    }
}

static atomic_int senhas_restantes;

typedef struct {
    long long start_index;
    long long end_index;
    int total_contas;
    uint64_t* hashes_alvo;
    char** senhas_encontradas;
    atomic_int* flags_encontrado;
    int thread_id;
} ThreadArg;

int index_to_password(long long global_index, char* password_buffer) {
    long long c2 = ALFABETO_LEN * ALFABETO_LEN;
    long long c3 = c2 * ALFABETO_LEN;
    if (global_index < c2) {
        password_buffer[0] = alfabeto[global_index / ALFABETO_LEN];
        password_buffer[1] = alfabeto[global_index % ALFABETO_LEN];
        password_buffer[2] = '\0';
        return 2;
    }
    global_index -= c2;
    if (global_index < c3) {
        password_buffer[0] = alfabeto[global_index / c2];
        password_buffer[1] = alfabeto[(global_index / ALFABETO_LEN) % ALFABETO_LEN];
        password_buffer[2] = alfabeto[global_index % ALFABETO_LEN];
        password_buffer[3] = '\0';
        return 3;
    }
    global_index -= c3;
    password_buffer[0] = alfabeto[global_index / c3];
    password_buffer[1] = alfabeto[(global_index / c2) % ALFABETO_LEN];
    password_buffer[2] = alfabeto[(global_index / ALFABETO_LEN) % ALFABETO_LEN];
    password_buffer[3] = alfabeto[global_index % ALFABETO_LEN];
    password_buffer[4] = '\0';
    return 4;
}

void* worker(void* arg) {
    ThreadArg* t = (ThreadArg*)arg;
    char password[MAX_PASSWORD_LEN + 1];
    uint8_t raw_hash[8] __attribute__((aligned(64)));
    uint64_t h64;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(t->thread_id % CPU_SETSIZE, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    for (long long i = t->start_index; i < t->end_index; i++) {
        if (atomic_load_explicit(&senhas_restantes, memory_order_relaxed) == 0) break;
        int len = index_to_password(i, password);
        MAO_64(raw_hash, password, len);
        h64 = 0;
        for (int b = 0; b < 8; b++) h64 = (h64 << 8) | raw_hash[b];

        for (int a = 0; a < t->total_contas; a++) {
            if (h64 == t->hashes_alvo[a] && atomic_load_explicit(&t->flags_encontrado[a], memory_order_relaxed) == 0) {
                if (atomic_exchange_explicit(&t->flags_encontrado[a], 1, memory_order_acq_rel) == 0) {
                    strcpy(t->senhas_encontradas[a], password);
                    atomic_fetch_sub_explicit(&senhas_restantes, 1, memory_order_acq_rel);
                }
            }
        }
    }
    return NULL;
}

uint64_t parse_hex_fast(const char* s) {
    uint64_t result = 0;
    char c;
    while ((c = *s++)) {
        result <<= 4;
        if (c >= '0' && c <= '9') result |= (c - '0');
        else if (c >= 'A' && c <= 'F') result |= (c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') result |= (c - 'a' + 10);
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <entrada> <saida>\n", argv[0]);
        return 1;
    }
    FILE* in = fopen(argv[1], "r");
    if (!in) { perror(argv[1]); return 1; }
    int n;
    if (fscanf(in, "%d\n", &n) != 1) { fclose(in); return 1; }
    atomic_init(&senhas_restantes, n);

    char** logins = malloc(n * sizeof(char*));
    uint64_t* hashes = malloc(n * sizeof(uint64_t));
    char** senhas = malloc(n * sizeof(char*));
    atomic_int* flags = calloc(n, sizeof(atomic_int));
    for (int i = 0; i < n; i++) {
        char line[128];
        if (!fgets(line, sizeof(line), in)) { fclose(in); return 1; }
        line[strcspn(line, "\r\n")] = '\0';
        char* p = strchr(line, ':'); *p = '\0';
        logins[i] = strdup(line);
        hashes[i] = parse_hex_fast(p+1);
        senhas[i] = malloc(MAX_PASSWORD_LEN+1);
        atomic_init(&flags[i], 0);
    }
    fclose(in);

    long long c2 = (long long)ALFABETO_LEN * ALFABETO_LEN;
    long long c3 = c2 * ALFABETO_LEN;
    long long c4 = c3 * ALFABETO_LEN;
    long long total = c2 + c3 + c4;
    long long chunk = total / NUM_THREADS;

    pthread_t th[NUM_THREADS];
    ThreadArg args[NUM_THREADS];
    for (int t = 0; t < NUM_THREADS; t++) {
        args[t].thread_id = t;
        args[t].start_index = t * chunk;
        args[t].end_index = (t == NUM_THREADS-1) ? total : (t+1)*chunk;
        args[t].total_contas = n;
        args[t].hashes_alvo = hashes;
        args[t].senhas_encontradas = senhas;
        args[t].flags_encontrado = flags;
        pthread_create(&th[t], NULL, worker, &args[t]);
    }
    for (int t = 0; t < NUM_THREADS; t++) pthread_join(th[t], NULL);

    FILE* out = fopen(argv[2], "w");
    if (!out) { perror(argv[2]); return 1; }
    for (int i = 0; i < n; i++) {
        fprintf(out, "%s:%s\n", logins[i], atomic_load(&flags[i]) ? senhas[i] : "NOT_FOUND");
    }
    fclose(out);

    for (int i = 0; i < n; i++) {
        free(logins[i]); free(senhas[i]);
    }
    free(logins); free(hashes); free(senhas); free(flags);
    return 0;
}
