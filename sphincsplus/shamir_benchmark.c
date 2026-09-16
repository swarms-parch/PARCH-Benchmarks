#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gmp.h>


/*
 * Match the swarm configuration used in comparison.
 *
 * Example:
 * n = 10 CHs
 * threshold t = 6
 */
#define N_SHARES 10
#define THRESHOLD 6

#define ITERATIONS 1000
#define WARMUP 200


/* ============================================================
 * Timing
 * ============================================================ */

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(
        CLOCK_MONOTONIC,
        &ts
    );

    return
        ((uint64_t)ts.tv_sec *
         1000000000ULL)
        +
        (uint64_t)ts.tv_nsec;
}


static int cmp_u64(
    const void *a,
    const void *b)
{
    uint64_t x =
        *(const uint64_t *)a;

    uint64_t y =
        *(const uint64_t *)b;

    if (x < y) return -1;
    if (x > y) return 1;

    return 0;
}


static void print_statistics(
    uint64_t *times)
{
    long double sum = 0.0;

    for (int i = 0;
         i < ITERATIONS;
         i++)
    {
        sum += times[i];
    }

    double avg =
        (double)(
            sum / ITERATIONS
        );


    uint64_t sorted[
        ITERATIONS
    ];

    memcpy(
        sorted,
        times,
        sizeof(sorted)
    );

    qsort(
        sorted,
        ITERATIONS,
        sizeof(uint64_t),
        cmp_u64
    );


    double median =
        (
            sorted[
                ITERATIONS/2 - 1
            ]
            +
            sorted[
                ITERATIONS/2
            ]
        ) / 2.0;


    long double variance = 0;

    for (int i = 0;
         i < ITERATIONS;
         i++)
    {
        long double d =
            times[i] - avg;

        variance += d*d;
    }

    variance /=
        ITERATIONS - 1;


    printf(
        "============================================================\n"
    );

    printf(
        "Shamir Secret Reconstruction / Lagrange Interpolation\n"
    );

    printf(
        "============================================================\n"
    );

    printf(
        "Total shares n   : %d\n",
        N_SHARES
    );

    printf(
        "Threshold t      : %d\n",
        THRESHOLD
    );

    printf(
        "Iterations       : %d\n",
        ITERATIONS
    );

    printf(
        "Warm-up          : %d\n\n",
        WARMUP
    );

    printf(
        "Average Time     : %.2f ns\n",
        avg
    );

    printf(
        "Median Time      : %.2f ns\n",
        median
    );

    printf(
        "Minimum Time     : %llu ns\n",
        (unsigned long long)
        sorted[0]
    );

    printf(
        "Maximum Time     : %llu ns\n",
        (unsigned long long)
        sorted[ITERATIONS-1]
    );

    printf(
        "Std. Deviation   : %.2f ns\n\n",
        sqrt((double)variance)
    );

    printf(
        "Average = %.3f us\n",
        avg / 1000.0
    );

    printf(
        "Average = %.6f ms\n",
        avg / 1e6
    );
}


/* ============================================================
 * Polynomial evaluation
 * ============================================================ */

static void polynomial_eval(
    mpz_t result,
    mpz_t *coeff,
    int degree,
    const mpz_t x,
    const mpz_t p)
{
    mpz_set(
        result,
        coeff[degree]
    );

    for (int i =
             degree - 1;
         i >= 0;
         i--)
    {
        mpz_mul(
            result,
            result,
            x
        );

        mpz_add(
            result,
            result,
            coeff[i]
        );

        mpz_mod(
            result,
            result,
            p
        );
    }
}


/* ============================================================
 * Scratch storage
 *
 * Reusing temporaries avoids repeatedly measuring heap
 * allocation instead of Shamir arithmetic.
 * ============================================================ */

typedef struct
{
    mpz_t sum;
    mpz_t numerator;
    mpz_t denominator;
    mpz_t difference;
    mpz_t inverse;
    mpz_t lambda;
    mpz_t temp;
}
shamir_scratch;


static void scratch_init(
    shamir_scratch *s)
{
    mpz_inits(
        s->sum,
        s->numerator,
        s->denominator,
        s->difference,
        s->inverse,
        s->lambda,
        s->temp,
        NULL
    );
}


static void scratch_clear(
    shamir_scratch *s)
{
    mpz_clears(
        s->sum,
        s->numerator,
        s->denominator,
        s->difference,
        s->inverse,
        s->lambda,
        s->temp,
        NULL
    );
}


/* ============================================================
 * Lagrange reconstruction at x=0
 * ============================================================ */

static int reconstruct_secret(
    mpz_t recovered,
    mpz_t *x,
    mpz_t *y,
    int t,
    const mpz_t p,
    shamir_scratch *s)
{
    mpz_set_ui(
        s->sum,
        0
    );


    for (int i = 0;
         i < t;
         i++)
    {
        mpz_set_ui(
            s->numerator,
            1
        );

        mpz_set_ui(
            s->denominator,
            1
        );


        for (int j = 0;
             j < t;
             j++)
        {
            if (i == j)
                continue;


            /*
             * Numerator *= -x_j
             */
            mpz_neg(
                s->temp,
                x[j]
            );

            mpz_mul(
                s->numerator,
                s->numerator,
                s->temp
            );

            mpz_mod(
                s->numerator,
                s->numerator,
                p
            );


            /*
             * Denominator *= x_i - x_j
             */
            mpz_sub(
                s->difference,
                x[i],
                x[j]
            );

            mpz_mul(
                s->denominator,
                s->denominator,
                s->difference
            );

            mpz_mod(
                s->denominator,
                s->denominator,
                p
            );
        }


        if (mpz_invert(
                s->inverse,
                s->denominator,
                p) == 0)
        {
            return 0;
        }


        mpz_mul(
            s->lambda,
            s->numerator,
            s->inverse
        );

        mpz_mod(
            s->lambda,
            s->lambda,
            p
        );


        mpz_mul(
            s->temp,
            y[i],
            s->lambda
        );

        mpz_add(
            s->sum,
            s->sum,
            s->temp
        );

        mpz_mod(
            s->sum,
            s->sum,
            p
        );
    }


    mpz_set(
        recovered,
        s->sum
    );

    return 1;
}


/* ============================================================
 * Main
 * ============================================================ */

int main(void)
{
    /*
     * 256-bit prime:
     *
     * p = 2^256 - 2^32 - 977
     */
    mpz_t p;

    mpz_init_set_str(
        p,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    );


    gmp_randstate_t state;

    gmp_randinit_default(
        state
    );

    /*
     * Fixed seed makes benchmark reproducible.
     */
    gmp_randseed_ui(
        state,
        20260826
    );


    mpz_t secret;

    mpz_init(secret);

    mpz_urandomm(
        secret,
        state,
        p
    );


    /*
     * Polynomial coefficients:
     *
     * f(x) = secret + a1*x + ... + a_(t-1)*x^(t-1)
     */
    mpz_t coeff[
        THRESHOLD
    ];

    for (int i = 0;
         i < THRESHOLD;
         i++)
    {
        mpz_init(
            coeff[i]
        );
    }


    mpz_set(
        coeff[0],
        secret
    );


    for (int i = 1;
         i < THRESHOLD;
         i++)
    {
        mpz_urandomm(
            coeff[i],
            state,
            p
        );
    }


    mpz_t x[
        N_SHARES
    ];

    mpz_t y[
        N_SHARES
    ];


    for (int i = 0;
         i < N_SHARES;
         i++)
    {
        mpz_init_set_ui(
            x[i],
            i + 1
        );

        mpz_init(
            y[i]
        );


        polynomial_eval(
            y[i],
            coeff,
            THRESHOLD - 1,
            x[i],
            p
        );
    }


    mpz_t recovered;

    mpz_init(
        recovered
    );


    shamir_scratch scratch;

    scratch_init(
        &scratch
    );


    /*
     * Correctness check
     */
    if (!reconstruct_secret(
            recovered,
            x,
            y,
            THRESHOLD,
            p,
            &scratch))
    {
        printf(
            "Reconstruction error\n"
        );

        return 1;
    }


    if (mpz_cmp(
            secret,
            recovered) != 0)
    {
        printf(
            "ERROR: Reconstructed secret differs\n"
        );

        return 1;
    }


    printf(
        "Shamir correctness check: PASSED\n\n"
    );


    /*
     * Warm-up
     */
    for (int i = 0;
         i < WARMUP;
         i++)
    {
        reconstruct_secret(
            recovered,
            x,
            y,
            THRESHOLD,
            p,
            &scratch
        );
    }


    /*
     * Timed benchmark
     */
    uint64_t times[
        ITERATIONS
    ];


    for (int i = 0;
         i < ITERATIONS;
         i++)
    {
        uint64_t start =
            now_ns();


        reconstruct_secret(
            recovered,
            x,
            y,
            THRESHOLD,
            p,
            &scratch
        );


        uint64_t end =
            now_ns();


        times[i] =
            end - start;
    }


    print_statistics(
        times
    );


    /* Cleanup */

    scratch_clear(
        &scratch
    );

    mpz_clear(
        recovered
    );

    for (int i = 0;
         i < N_SHARES;
         i++)
    {
        mpz_clear(x[i]);
        mpz_clear(y[i]);
    }

    for (int i = 0;
         i < THRESHOLD;
         i++)
    {
        mpz_clear(
            coeff[i]
        );
    }

    mpz_clear(
        secret
    );

    mpz_clear(
        p
    );

    gmp_randclear(
        state
    );


    return 0;
}