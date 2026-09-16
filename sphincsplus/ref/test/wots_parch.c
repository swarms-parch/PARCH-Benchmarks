#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "../params.h"
#include "../context.h"
#include "../hash.h"
#include "../thash.h"
#include "../wots.h"
#include "../address.h"


/* ============================================================
 * BENCHMARK PARAMETERS
 * ============================================================ */

#define ITERATIONS 1000
#define WARMUP 200


/* ============================================================
 * HIGH-RESOLUTION TIMER
 * ============================================================ */

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(
        CLOCK_MONOTONIC,
        &ts
    );

    return
        ((uint64_t)ts.tv_sec * 1000000000ULL)
        +
        (uint64_t)ts.tv_nsec;
}


/* ============================================================
 * STATISTICS
 * ============================================================ */

static int compare_u64(
    const void *a,
    const void *b
)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    if (x < y)
        return -1;

    if (x > y)
        return 1;

    return 0;
}


static double mean_u64(
    const uint64_t *values,
    size_t n
)
{
    long double sum = 0.0;

    for (size_t i = 0; i < n; i++)
    {
        sum += values[i];
    }

    return (double)(sum / n);
}


static double stddev_u64(
    const uint64_t *values,
    size_t n,
    double mean
)
{
    long double sum = 0.0;

    for (size_t i = 0; i < n; i++)
    {
        long double diff =
            (long double)values[i] - mean;

        sum += diff * diff;
    }

    return sqrt(
        (double)(sum / (n - 1))
    );
}


static double print_statistics(
    const char *name,
    uint64_t *times
)
{
    double average =
        mean_u64(
            times,
            ITERATIONS
        );

    double std =
        stddev_u64(
            times,
            ITERATIONS,
            average
        );

    uint64_t sorted[ITERATIONS];

    memcpy(
        sorted,
        times,
        sizeof(sorted)
    );

    qsort(
        sorted,
        ITERATIONS,
        sizeof(uint64_t),
        compare_u64
    );

    double median;

    if (ITERATIONS % 2 == 0)
    {
        median =
            (
                (double)sorted[
                    ITERATIONS / 2 - 1
                ]
                +
                (double)sorted[
                    ITERATIONS / 2
                ]
            )
            / 2.0;
    }
    else
    {
        median =
            sorted[
                ITERATIONS / 2
            ];
    }


    printf(
        "============================================================\n"
    );

    printf(
        "%s\n",
        name
    );

    printf(
        "============================================================\n"
    );

    printf(
        "Iterations       : %d\n",
        ITERATIONS
    );

    printf(
        "Warm-up          : %d\n",
        WARMUP
    );

    printf("\n");

    printf(
        "Average Time     : %.2f ns\n",
        average
    );

    printf(
        "Median Time      : %.2f ns\n",
        median
    );

    printf(
        "Minimum Time     : %llu ns\n",
        (unsigned long long)sorted[0]
    );

    printf(
        "Maximum Time     : %llu ns\n",
        (unsigned long long)
            sorted[
                ITERATIONS - 1
            ]
    );

    printf(
        "Std. Deviation   : %.2f ns\n",
        std
    );

    printf("\n");

    printf(
        "Average = %.3f us\n",
        average / 1000.0
    );

    printf(
        "Average = %.6f ms\n",
        average / 1e6
    );

    printf("\n");

    return average;
}


/* ============================================================
 * WOTS HASH-CHAIN OPERATION
 *
 * This mirrors the chain operation used in the official
 * SPHINCS+ WOTS implementation.
 * ============================================================ */

static void generate_chain(
    unsigned char *out,
    const unsigned char *in,
    unsigned int start,
    unsigned int steps,
    const spx_ctx *ctx,
    uint32_t addr[8]
)
{
    memcpy(
        out,
        in,
        SPX_N
    );

    for (
        unsigned int i = start;
        i < start + steps &&
        i < SPX_WOTS_W;
        i++
    )
    {
        set_hash_addr(
            addr,
            i
        );

        thash(
            out,
            out,
            1,
            ctx,
            addr
        );
    }
}


/* ============================================================
 * WOTS+ PUBLIC-KEY GENERATION
 *
 * This is the complete WOTS public-key generation operation.
 *
 * It generates:
 *
 *     sk_1 -> chain endpoint
 *     sk_2 -> chain endpoint
 *     ...
 *
 * and compresses all chain endpoints into one SPX_N-byte
 * public key.
 *
 * 
 * ============================================================ */

static void wots_keygen(
    unsigned char *compressed_pk,
    const spx_ctx *ctx,
    uint32_t wots_addr[8],
    uint32_t pk_addr[8]
)
{
    unsigned char full_pk[
        SPX_WOTS_BYTES
    ];


    for (
        unsigned int i = 0;
        i < SPX_WOTS_LEN;
        i++
    )
    {
        unsigned char *pk_i =
            full_pk + i * SPX_N;


        /* --------------------------------------------
         * Generate WOTS secret chain element
         * -------------------------------------------- */

        set_chain_addr(
            wots_addr,
            i
        );

        set_hash_addr(
            wots_addr,
            0
        );

        set_type(
            wots_addr,
            SPX_ADDR_TYPE_WOTSPRF
        );

        prf_addr(
            pk_i,
            ctx,
            wots_addr
        );


        /* --------------------------------------------
         * Move to the top of the WOTS hash chain
         * -------------------------------------------- */

        set_type(
            wots_addr,
            SPX_ADDR_TYPE_WOTS
        );

        generate_chain(
            pk_i,
            pk_i,
            0,
            SPX_WOTS_W - 1,
            ctx,
            wots_addr
        );
    }


    /* ------------------------------------------------
     * Compress all WOTS chain endpoints
     * ------------------------------------------------ */

    thash(
        compressed_pk,
        full_pk,
        SPX_WOTS_LEN,
        ctx,
        pk_addr
    );
}


/* ============================================================
 * WOTS+ SIGNING
 *
 * ============================================================ */

static void wots_sign_parch(
    unsigned char *signature,
    const unsigned char *message,
    const spx_ctx *ctx,
    uint32_t wots_addr[8]
)
{
    unsigned int lengths[
        SPX_WOTS_LEN
    ];


    chain_lengths(
        lengths,
        message
    );


    for (
        unsigned int i = 0;
        i < SPX_WOTS_LEN;
        i++
    )
    {
        unsigned char *sig_i =
            signature + i * SPX_N;


        /* --------------------------------------------
         * Generate secret value for this WOTS chain
         * -------------------------------------------- */

        set_chain_addr(
            wots_addr,
            i
        );

        set_hash_addr(
            wots_addr,
            0
        );

        set_type(
            wots_addr,
            SPX_ADDR_TYPE_WOTSPRF
        );

        prf_addr(
            sig_i,
            ctx,
            wots_addr
        );


        /* --------------------------------------------
         * Move along chain to message-selected point
         * -------------------------------------------- */

        set_type(
            wots_addr,
            SPX_ADDR_TYPE_WOTS
        );

        generate_chain(
            sig_i,
            sig_i,
            0,
            lengths[i],
            ctx,
            wots_addr
        );
    }
}


/* ============================================================
 * WOTS+ VERIFICATION
 *
 * ============================================================ */

static int wots_verify_parch(
    const unsigned char *signature,
    const unsigned char *message,
    const unsigned char *expected_pk,
    const spx_ctx *ctx,
    uint32_t wots_addr[8],
    uint32_t pk_addr[8]
)
{
    unsigned char reconstructed_full_pk[
        SPX_WOTS_BYTES
    ];

    unsigned char reconstructed_pk[
        SPX_N
    ];


    /*
     * Official SPHINCS+ routine.
     *
     */
    wots_pk_from_sig(
        reconstructed_full_pk,
        signature,
        message,
        ctx,
        wots_addr
    );


    /*
     */
    thash(
        reconstructed_pk,
        reconstructed_full_pk,
        SPX_WOTS_LEN,
        ctx,
        pk_addr
    );


    return memcmp(
        reconstructed_pk,
        expected_pk,
        SPX_N
    ) == 0;
}


/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    spx_ctx ctx;



    for (
        unsigned int i = 0;
        i < SPX_N;
        i++
    )
    {
        ctx.sk_seed[i] =
            (unsigned char)(
                i + 1
            );

        ctx.pub_seed[i] =
            (unsigned char)(
                0xA0 + i
            );
    }



    initialize_hash_function(
        &ctx
    );


    /* ========================================================
     * WOTS message digest
     *
     * WOTS signs an n-byte digest
     * ======================================================== */

    unsigned char message[
        SPX_N
    ];

    for (
        unsigned int i = 0;
        i < SPX_N;
        i++
    )
    {
        message[i] =
            (unsigned char)(
                0x20 + i
            );
    }


    /* ========================================================
     * Buffers
     * ======================================================== */

    unsigned char public_key[
        SPX_N
    ];

    unsigned char signature[
        SPX_WOTS_BYTES
    ];


    /* ========================================================
     * Addresses
     * ======================================================== */

    uint32_t wots_addr[8] =
        {0};

    uint32_t pk_addr[8] =
        {0};


 
    set_keypair_addr(
        wots_addr,
        0
    );

    set_keypair_addr(
        pk_addr,
        0
    );

    set_type(
        wots_addr,
        SPX_ADDR_TYPE_WOTS
    );

    set_type(
        pk_addr,
        SPX_ADDR_TYPE_WOTSPK
    );


    /* ========================================================
     * Benchmark arrays
     * ======================================================== */

    uint64_t keygen_times[
        ITERATIONS
    ];

    uint64_t sign_times[
        ITERATIONS
    ];

    uint64_t verify_times[
        ITERATIONS
    ];


    /* ========================================================
     * Print WOTS parameters
     * ======================================================== */

    printf(
        "============================================================\n"
    );

    printf(
        "PARCH WOTS+ PARAMETER SET\n"
    );

    printf(
        "============================================================\n"
    );

    printf(
        "SPX_N            : %d bytes\n",
        SPX_N
    );

    printf(
        "Winternitz w     : %d\n",
        SPX_WOTS_W
    );

    printf(
        "WOTS len1        : %d\n",
        SPX_WOTS_LEN1
    );

    printf(
        "WOTS len2        : %d\n",
        SPX_WOTS_LEN2
    );

    printf(
        "WOTS chains      : %d\n",
        SPX_WOTS_LEN
    );

    printf(
        "Signature bytes  : %d\n",
        SPX_WOTS_BYTES
    );

    printf(
        "Iterations       : %d\n",
        ITERATIONS
    );

    printf(
        "Warm-up          : %d\n",
        WARMUP
    );

    printf("\n");


    /* ========================================================
     * CORRECTNESS CHECK
     * ======================================================== */

    wots_keygen(
        public_key,
        &ctx,
        wots_addr,
        pk_addr
    );


    wots_sign_parch(
        signature,
        message,
        &ctx,
        wots_addr
    );


    int valid =
        wots_verify_parch(
            signature,
            message,
            public_key,
            &ctx,
            wots_addr,
            pk_addr
        );


    if (!valid)
    {
        printf(
            "ERROR: WOTS verification failed.\n"
        );

        return 1;
    }


    printf(
        "WOTS correctness check: PASSED\n\n"
    );


    /* ========================================================
     * WOTS KEY GENERATION WARM-UP
     * ======================================================== */

    for (
        int i = 0;
        i < WARMUP;
        i++
    )
    {
        wots_keygen(
            public_key,
            &ctx,
            wots_addr,
            pk_addr
        );
    }


    /* ========================================================
     * WOTS KEY GENERATION BENCHMARK
     * ======================================================== */

    for (
        int i = 0;
        i < ITERATIONS;
        i++
    )
    {
        uint64_t start =
            now_ns();


        wots_keygen(
            public_key,
            &ctx,
            wots_addr,
            pk_addr
        );


        uint64_t end =
            now_ns();


        keygen_times[i] =
            end - start;
    }


    /* ========================================================
     * WOTS SIGNING WARM-UP
     * ======================================================== */

    for (
        int i = 0;
        i < WARMUP;
        i++
    )
    {
        wots_sign_parch(
            signature,
            message,
            &ctx,
            wots_addr
        );
    }


    /* ========================================================
     * WOTS SIGNING BENCHMARK
     * ======================================================== */

    for (
        int i = 0;
        i < ITERATIONS;
        i++
    )
    {
        uint64_t start =
            now_ns();


        wots_sign_parch(
            signature,
            message,
            &ctx,
            wots_addr
        );


        uint64_t end =
            now_ns();


        sign_times[i] =
            end - start;
    }



    wots_sign_parch(
        signature,
        message,
        &ctx,
        wots_addr
    );


    /* ========================================================
     * WOTS VERIFICATION WARM-UP
     * ======================================================== */

    for (
        int i = 0;
        i < WARMUP;
        i++
    )
    {
        valid =
            wots_verify_parch(
                signature,
                message,
                public_key,
                &ctx,
                wots_addr,
                pk_addr
            );


        if (!valid)
        {
            printf(
                "Verification failed during warm-up.\n"
            );

            return 1;
        }
    }


    /* ========================================================
     * WOTS VERIFICATION BENCHMARK
     * ======================================================== */

    for (
        int i = 0;
        i < ITERATIONS;
        i++
    )
    {
        uint64_t start =
            now_ns();


        valid =
            wots_verify_parch(
                signature,
                message,
                public_key,
                &ctx,
                wots_addr,
                pk_addr
            );


        uint64_t end =
            now_ns();


        if (!valid)
        {
            printf(
                "Verification failed during benchmark.\n"
            );

            return 1;
        }


        verify_times[i] =
            end - start;
    }


    /* ========================================================
     * RESULTS
     * ======================================================== */

    double T_WKG =
        print_statistics(
            "WOTS+ Public-Key Generation Benchmark",
            keygen_times
        );


    double T_WS =
        print_statistics(
            "WOTS+ Signing Benchmark",
            sign_times
        );


    double T_WV =
        print_statistics(
            "WOTS+ Verification Benchmark",
            verify_times
        );


    /* ========================================================
     * SUMMARY
     * ======================================================== */

    printf(
        "============================================================\n"
    );

    printf(
        "PARCH WOTS+ SUMMARY\n"
    );

    printf(
        "============================================================\n"
    );


    printf(
        "WOTS KeyGen     : %.3f us\n",
        T_WKG / 1000.0
    );

    printf(
        "WOTS Sign       : %.3f us\n",
        T_WS / 1000.0
    );

    printf(
        "WOTS Verify     : %.3f us\n",
        T_WV / 1000.0
    );






    return 0;
}
