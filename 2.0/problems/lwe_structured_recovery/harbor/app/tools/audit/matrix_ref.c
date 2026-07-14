/*
 * Independent public matrix reconstruction oracle for Frontier-CS.
 *
 * SHAKE-256 and Keccak-f[1600] below are implemented directly from FIPS PUB
 * 202. The standardized round constants and rotation offsets were
 * cross-checked against Markku-Juhani O. Saarinen's tiny_sha3 implementation
 * (CC0, https://github.com/mjosaarinen/tiny_sha3). This file was written as a
 * standalone C11 implementation: it does not call Python or share generated
 * code or tables with the Python materializer.
 *
 * The program accepts public matrix-generation metadata only. It has no
 * interface for secrets, errors, residuals, or witness checking.
 */

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHAKE256_RATE 136U
#define SHAKE_BLOCK_SIZE 64U
#define MATRIX_N_MAX 4096U

enum matrix_kind {
    KIND_UNSET = 0,
    KIND_UNIFORM,
    KIND_SMALL_ALPHABET,
    KIND_SPARSE_UNIFORM,
    KIND_SPARSE_SMALL_ALPHABET
};

struct options {
    uint8_t seed[32];
    const char *domain;
    size_t domain_len;
    const char *instance_id;
    size_t instance_id_len;
    uint32_t n;
    uint32_t q;
    enum matrix_kind kind;
    int64_t *alphabet;
    uint32_t alphabet_len;
    uint32_t row_weight;
    uint64_t start;
    uint64_t stop;
};

struct shake_ctx {
    uint64_t lanes[25];
    size_t position;
};

struct shake_stream {
    const uint8_t *domain;
    size_t domain_len;
    const uint8_t *seed;
    uint64_t next_block;
    bool no_more_blocks;
    uint8_t buffer[SHAKE_BLOCK_SIZE];
    size_t position;
};

static void print_usage(void)
{
    (void)fprintf(
        stderr,
        "usage: matrix_ref --seed HEX64 --domain TEXT --instance-id ASCII "
        "--n N --q Q --kind KIND [--alphabet CSV] [--row-weight K] "
        "--start START --stop STOP\n");
}

static int usage_error(const char *message)
{
    (void)fprintf(stderr, "error: %s\n", message);
    print_usage();
    return 2;
}

static bool parse_u64(const char *text, uint64_t maximum, uint64_t *result)
{
    uint64_t value = 0;
    const unsigned char *cursor = (const unsigned char *)text;

    if (*cursor == '\0') {
        return false;
    }
    while (*cursor != '\0') {
        unsigned int digit;
        if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9') {
            return false;
        }
        digit = (unsigned int)(*cursor - (unsigned char)'0');
        if (value > (maximum - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
        ++cursor;
    }
    *result = value;
    return true;
}

static bool parse_i64_token(const char *text, size_t length, int64_t *result)
{
    size_t index = 0;
    bool negative = false;
    uint64_t value = 0;
    uint64_t limit;

    if (length == 0U) {
        return false;
    }
    if (text[index] == '-' || text[index] == '+') {
        negative = text[index] == '-';
        ++index;
        if (index == length) {
            return false;
        }
    }
    limit = negative ? (UINT64_C(1) << 63) : (uint64_t)INT64_MAX;
    for (; index < length; ++index) {
        unsigned int digit;
        unsigned char byte = (unsigned char)text[index];
        if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
            return false;
        }
        digit = (unsigned int)(byte - (unsigned char)'0');
        if (value > (limit - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
    }
    if (negative) {
        if (value == (UINT64_C(1) << 63)) {
            *result = INT64_MIN;
        } else {
            *result = -(int64_t)value;
        }
    } else {
        *result = (int64_t)value;
    }
    return true;
}

static int hex_nibble(unsigned char byte)
{
    if (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') {
        return (int)(byte - (unsigned char)'0');
    }
    byte = (unsigned char)tolower((int)byte);
    if (byte >= (unsigned char)'a' && byte <= (unsigned char)'f') {
        return (int)(byte - (unsigned char)'a') + 10;
    }
    return -1;
}

static bool parse_seed(const char *text, uint8_t seed[32])
{
    size_t index;
    if (strlen(text) != 64U) {
        return false;
    }
    for (index = 0; index < 32U; ++index) {
        int high = hex_nibble((unsigned char)text[2U * index]);
        int low = hex_nibble((unsigned char)text[2U * index + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        seed[index] = (uint8_t)((unsigned int)high * 16U + (unsigned int)low);
    }
    return true;
}

static bool valid_utf8(const unsigned char *text, size_t length)
{
    size_t index = 0;
    while (index < length) {
        unsigned char first = text[index++];
        if (first <= 0x7fU) {
            continue;
        }
        if (first >= 0xc2U && first <= 0xdfU) {
            if (index >= length || text[index] < 0x80U || text[index] > 0xbfU) {
                return false;
            }
            ++index;
            continue;
        }
        if (first >= 0xe0U && first <= 0xefU) {
            unsigned char second;
            unsigned char third;
            if (length - index < 2U) {
                return false;
            }
            second = text[index];
            third = text[index + 1U];
            if (second < 0x80U || second > 0xbfU ||
                third < 0x80U || third > 0xbfU ||
                (first == 0xe0U && second < 0xa0U) ||
                (first == 0xedU && second > 0x9fU)) {
                return false;
            }
            index += 2U;
            continue;
        }
        if (first >= 0xf0U && first <= 0xf4U) {
            unsigned char second;
            unsigned char third;
            unsigned char fourth;
            if (length - index < 3U) {
                return false;
            }
            second = text[index];
            third = text[index + 1U];
            fourth = text[index + 2U];
            if (second < 0x80U || second > 0xbfU ||
                third < 0x80U || third > 0xbfU ||
                fourth < 0x80U || fourth > 0xbfU ||
                (first == 0xf0U && second < 0x90U) ||
                (first == 0xf4U && second > 0x8fU)) {
                return false;
            }
            index += 3U;
            continue;
        }
        return false;
    }
    return true;
}

static bool valid_instance_id(const char *text, size_t length)
{
    size_t index;
    unsigned char first;
    if (length == 0U || length > 64U) {
        return false;
    }
    first = (unsigned char)text[0];
    if (!((first >= (unsigned char)'A' && first <= (unsigned char)'Z') ||
          (first >= (unsigned char)'a' && first <= (unsigned char)'z') ||
          (first >= (unsigned char)'0' && first <= (unsigned char)'9'))) {
        return false;
    }
    for (index = 1U; index < length; ++index) {
        unsigned char byte = (unsigned char)text[index];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'_' ||
              byte == (unsigned char)'-')) {
            return false;
        }
    }
    return true;
}

static enum matrix_kind parse_kind(const char *text)
{
    if (strcmp(text, "uniform") == 0) {
        return KIND_UNIFORM;
    }
    if (strcmp(text, "small_alphabet") == 0) {
        return KIND_SMALL_ALPHABET;
    }
    if (strcmp(text, "sparse_uniform") == 0) {
        return KIND_SPARSE_UNIFORM;
    }
    if (strcmp(text, "sparse_small_alphabet") == 0) {
        return KIND_SPARSE_SMALL_ALPHABET;
    }
    return KIND_UNSET;
}

static bool parse_alphabet(
    const char *text,
    uint32_t q,
    bool exclude_zero,
    int64_t **values_out,
    uint32_t *count_out)
{
    size_t text_length = strlen(text);
    size_t count = 1U;
    size_t start = 0U;
    size_t index;
    int64_t *values;
    int64_t lower = -(int64_t)(q / 2U);
    int64_t upper = (int64_t)((q - 1U) / 2U);

    if (text_length == 0U) {
        return false;
    }
    for (index = 0U; index < text_length; ++index) {
        if (text[index] == ',') {
            if (count == UINT32_MAX) {
                return false;
            }
            ++count;
        }
    }
    if (count > SIZE_MAX / sizeof(*values)) {
        return false;
    }
    values = (int64_t *)malloc(count * sizeof(*values));
    if (values == NULL) {
        return false;
    }
    count = 0U;
    for (index = 0U; index <= text_length; ++index) {
        if (index == text_length || text[index] == ',') {
            int64_t value;
            if (!parse_i64_token(text + start, index - start, &value) ||
                value < lower || value > upper ||
                (count > 0U && values[count - 1U] >= value) ||
                (exclude_zero && value == 0)) {
                free(values);
                return false;
            }
            values[count++] = value;
            start = index + 1U;
        }
    }
    *values_out = values;
    *count_out = (uint32_t)count;
    return true;
}

static uint64_t rotate_left(uint64_t value, unsigned int shift)
{
    if (shift == 0U) {
        return value;
    }
    return (value << shift) | (value >> (64U - shift));
}

static void keccak_f1600(uint64_t lanes[25])
{
    static const uint64_t round_constants[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };
    static const unsigned int rotation_offsets[25] = {
         0U,  1U, 62U, 28U, 27U,
        36U, 44U,  6U, 55U, 20U,
         3U, 10U, 43U, 25U, 39U,
        41U, 45U, 15U, 21U,  8U,
        18U,  2U, 61U, 56U, 14U
    };
    unsigned int round;

    for (round = 0U; round < 24U; ++round) {
        uint64_t columns[5];
        uint64_t theta[5];
        uint64_t permuted[25];
        unsigned int x;
        unsigned int y;

        for (x = 0U; x < 5U; ++x) {
            columns[x] = lanes[x] ^ lanes[x + 5U] ^ lanes[x + 10U] ^
                         lanes[x + 15U] ^ lanes[x + 20U];
        }
        for (x = 0U; x < 5U; ++x) {
            theta[x] = columns[(x + 4U) % 5U] ^
                       rotate_left(columns[(x + 1U) % 5U], 1U);
        }
        for (y = 0U; y < 5U; ++y) {
            for (x = 0U; x < 5U; ++x) {
                lanes[x + 5U * y] ^= theta[x];
            }
        }
        for (y = 0U; y < 5U; ++y) {
            for (x = 0U; x < 5U; ++x) {
                unsigned int new_x = y;
                unsigned int new_y = (2U * x + 3U * y) % 5U;
                permuted[new_x + 5U * new_y] =
                    rotate_left(lanes[x + 5U * y],
                                rotation_offsets[x + 5U * y]);
            }
        }
        for (y = 0U; y < 5U; ++y) {
            for (x = 0U; x < 5U; ++x) {
                lanes[x + 5U * y] =
                    permuted[x + 5U * y] ^
                    ((~permuted[(x + 1U) % 5U + 5U * y]) &
                     permuted[(x + 2U) % 5U + 5U * y]);
            }
        }
        lanes[0] ^= round_constants[round];
    }
}

static void shake_init(struct shake_ctx *ctx)
{
    (void)memset(ctx, 0, sizeof(*ctx));
}

static void shake_absorb(
    struct shake_ctx *ctx, const uint8_t *input, size_t input_length)
{
    size_t index;
    for (index = 0U; index < input_length; ++index) {
        size_t lane = ctx->position / 8U;
        unsigned int shift = (unsigned int)(8U * (ctx->position % 8U));
        ctx->lanes[lane] ^= (uint64_t)input[index] << shift;
        ++ctx->position;
        if (ctx->position == SHAKE256_RATE) {
            keccak_f1600(ctx->lanes);
            ctx->position = 0U;
        }
    }
}

static void shake_finalize(struct shake_ctx *ctx)
{
    size_t lane = ctx->position / 8U;
    unsigned int shift = (unsigned int)(8U * (ctx->position % 8U));
    size_t final_lane = (SHAKE256_RATE - 1U) / 8U;
    unsigned int final_shift =
        (unsigned int)(8U * ((SHAKE256_RATE - 1U) % 8U));

    ctx->lanes[lane] ^= UINT64_C(0x1f) << shift;
    ctx->lanes[final_lane] ^= UINT64_C(0x80) << final_shift;
    keccak_f1600(ctx->lanes);
    ctx->position = 0U;
}

static void shake_squeeze(
    struct shake_ctx *ctx, uint8_t *output, size_t output_length)
{
    size_t index;
    for (index = 0U; index < output_length; ++index) {
        size_t lane;
        unsigned int shift;
        if (ctx->position == SHAKE256_RATE) {
            keccak_f1600(ctx->lanes);
            ctx->position = 0U;
        }
        lane = ctx->position / 8U;
        shift = (unsigned int)(8U * (ctx->position % 8U));
        output[index] = (uint8_t)((ctx->lanes[lane] >> shift) & UINT64_C(0xff));
        ++ctx->position;
    }
}

static void store_le32(uint8_t output[4], uint32_t value)
{
    unsigned int index;
    for (index = 0U; index < 4U; ++index) {
        output[index] = (uint8_t)(value >> (8U * index));
    }
}

static void store_le64(uint8_t output[8], uint64_t value)
{
    unsigned int index;
    for (index = 0U; index < 8U; ++index) {
        output[index] = (uint8_t)(value >> (8U * index));
    }
}

static void stream_init(
    struct shake_stream *stream,
    const uint8_t *domain,
    size_t domain_len,
    const uint8_t seed[32])
{
    stream->domain = domain;
    stream->domain_len = domain_len;
    stream->seed = seed;
    stream->next_block = 0U;
    stream->no_more_blocks = false;
    stream->position = SHAKE_BLOCK_SIZE;
}

static bool stream_refill(struct shake_stream *stream)
{
    static const uint8_t separator = 0U;
    uint8_t encoded_block[8];
    struct shake_ctx ctx;

    if (stream->no_more_blocks) {
        return false;
    }
    store_le64(encoded_block, stream->next_block);
    shake_init(&ctx);
    shake_absorb(&ctx, stream->domain, stream->domain_len);
    shake_absorb(&ctx, &separator, 1U);
    shake_absorb(&ctx, stream->seed, 32U);
    shake_absorb(&ctx, encoded_block, sizeof(encoded_block));
    shake_finalize(&ctx);
    shake_squeeze(&ctx, stream->buffer, sizeof(stream->buffer));
    stream->position = 0U;
    if (stream->next_block == UINT64_MAX) {
        stream->no_more_blocks = true;
    } else {
        ++stream->next_block;
    }
    return true;
}

static bool stream_read(
    struct shake_stream *stream, uint8_t *output, size_t output_length)
{
    size_t written = 0U;
    while (written < output_length) {
        size_t available;
        size_t count;
        if (stream->position == SHAKE_BLOCK_SIZE && !stream_refill(stream)) {
            return false;
        }
        available = SHAKE_BLOCK_SIZE - stream->position;
        count = output_length - written;
        if (count > available) {
            count = available;
        }
        (void)memcpy(output + written, stream->buffer + stream->position, count);
        stream->position += count;
        written += count;
    }
    return true;
}

static bool stream_randbelow(
    struct shake_stream *stream, uint64_t upper, uint64_t *result)
{
    unsigned int width = 1U;
    uint64_t shifted;
    uint64_t range;
    uint64_t limit;

    if (upper == 0U || upper > UINT32_MAX) {
        return false;
    }
    shifted = upper - 1U;
    while (shifted > UINT64_C(0xff)) {
        ++width;
        shifted >>= 8U;
    }
    range = UINT64_C(1) << (8U * width);
    limit = (range / upper) * upper;
    for (;;) {
        uint8_t bytes[4];
        uint64_t value = 0U;
        unsigned int index;
        if (!stream_read(stream, bytes, width)) {
            return false;
        }
        for (index = 0U; index < width; ++index) {
            value |= (uint64_t)bytes[index] << (8U * index);
        }
        if (value < limit) {
            *result = value % upper;
            return true;
        }
    }
}

static int compare_u32(const void *left, const void *right)
{
    uint32_t first = *(const uint32_t *)left;
    uint32_t second = *(const uint32_t *)right;
    return (first > second) - (first < second);
}

static bool emit_value(uint32_t column, int64_t value)
{
    if (column != 0U && fputc(' ', stdout) == EOF) {
        return false;
    }
    return fprintf(stdout, "%" PRId64, value) >= 0;
}

static bool sample_dense_coefficient(
    const struct options *options,
    struct shake_stream *stream,
    int64_t *value)
{
    uint64_t sampled;
    if (options->kind == KIND_UNIFORM) {
        if (!stream_randbelow(stream, options->q, &sampled)) {
            return false;
        }
        *value = (int64_t)sampled;
        return true;
    }
    if (!stream_randbelow(stream, options->alphabet_len, &sampled)) {
        return false;
    }
    *value = options->alphabet[sampled];
    return true;
}

static bool sample_sparse_coefficient(
    const struct options *options,
    struct shake_stream *stream,
    int64_t *value)
{
    uint64_t sampled;
    if (options->kind == KIND_SPARSE_UNIFORM) {
        if (!stream_randbelow(stream, (uint64_t)options->q - 1U, &sampled)) {
            return false;
        }
        *value = (int64_t)(sampled + 1U);
        return true;
    }
    if (!stream_randbelow(stream, options->alphabet_len, &sampled)) {
        return false;
    }
    *value = options->alphabet[sampled];
    return true;
}

static bool emit_dense_row(
    const struct options *options, const uint8_t *row_domain, size_t domain_len)
{
    struct shake_stream stream;
    uint32_t column;
    stream_init(&stream, row_domain, domain_len, options->seed);
    for (column = 0U; column < options->n; ++column) {
        int64_t value;
        if (!sample_dense_coefficient(options, &stream, &value) ||
            !emit_value(column, value)) {
            return false;
        }
    }
    return fputc('\n', stdout) != EOF;
}

static bool emit_sparse_row(
    const struct options *options,
    uint8_t *row_domain,
    size_t domain_len,
    uint32_t *support,
    uint8_t *seen)
{
    struct shake_stream support_stream;
    struct shake_stream coefficient_stream;
    uint32_t support_count = 0U;
    uint32_t support_index = 0U;
    uint32_t column;

    row_domain[domain_len - 1U] = 0x02U;
    stream_init(&support_stream, row_domain, domain_len, options->seed);
    (void)memset(seen, 0, options->n);
    while (support_count < options->row_weight) {
        uint64_t candidate;
        if (!stream_randbelow(&support_stream, options->n, &candidate)) {
            return false;
        }
        if (seen[candidate] == 0U) {
            seen[candidate] = 1U;
            support[support_count++] = (uint32_t)candidate;
        }
    }
    qsort(support, options->row_weight, sizeof(*support), compare_u32);

    row_domain[domain_len - 1U] = 0x03U;
    stream_init(&coefficient_stream, row_domain, domain_len, options->seed);
    for (column = 0U; column < options->n; ++column) {
        int64_t value = 0;
        if (support_index < options->row_weight &&
            support[support_index] == column) {
            if (!sample_sparse_coefficient(options, &coefficient_stream, &value)) {
                return false;
            }
            ++support_index;
        }
        if (!emit_value(column, value)) {
            return false;
        }
    }
    return fputc('\n', stdout) != EOF;
}

static int materialize(const struct options *options)
{
    size_t prefix_len;
    size_t row_domain_len;
    uint8_t *row_domain = NULL;
    uint32_t *support = NULL;
    uint8_t *seen = NULL;
    uint64_t row;
    int status = 0;

    if (options->domain_len > UINT32_MAX ||
        options->domain_len > SIZE_MAX - options->instance_id_len - 17U) {
        return usage_error("domain is too long");
    }
    prefix_len = 4U + options->domain_len + 4U + options->instance_id_len;
    row_domain_len = prefix_len + 9U;
    row_domain = (uint8_t *)malloc(row_domain_len);
    if (row_domain == NULL) {
        (void)fprintf(stderr, "error: memory allocation failed\n");
        return 1;
    }
    store_le32(row_domain, (uint32_t)options->domain_len);
    (void)memcpy(row_domain + 4U, options->domain, options->domain_len);
    store_le32(row_domain + 4U + options->domain_len,
               (uint32_t)options->instance_id_len);
    (void)memcpy(row_domain + 8U + options->domain_len,
                 options->instance_id,
                 options->instance_id_len);

    if (options->kind == KIND_SPARSE_UNIFORM ||
        options->kind == KIND_SPARSE_SMALL_ALPHABET) {
        support = (uint32_t *)malloc((size_t)options->row_weight * sizeof(*support));
        seen = (uint8_t *)malloc(options->n);
        if (support == NULL || seen == NULL) {
            (void)fprintf(stderr, "error: memory allocation failed\n");
            status = 1;
            goto cleanup;
        }
    }

    for (row = options->start; row < options->stop; ++row) {
        bool ok;
        store_le64(row_domain + prefix_len, row);
        if (options->kind == KIND_UNIFORM ||
            options->kind == KIND_SMALL_ALPHABET) {
            row_domain[row_domain_len - 1U] = 0x01U;
            ok = emit_dense_row(options, row_domain, row_domain_len);
        } else {
            ok = emit_sparse_row(options,
                                 row_domain,
                                 row_domain_len,
                                 support,
                                 seen);
        }
        if (!ok) {
            (void)fprintf(stderr, "error: matrix output failed\n");
            status = 1;
            goto cleanup;
        }
    }
    if (fflush(stdout) == EOF) {
        (void)fprintf(stderr, "error: matrix output failed\n");
        status = 1;
    }

cleanup:
    free(seen);
    free(support);
    free(row_domain);
    return status;
}

int main(int argc, char **argv)
{
    enum {
        FLAG_SEED = 1U << 0,
        FLAG_DOMAIN = 1U << 1,
        FLAG_INSTANCE_ID = 1U << 2,
        FLAG_N = 1U << 3,
        FLAG_Q = 1U << 4,
        FLAG_KIND = 1U << 5,
        FLAG_ALPHABET = 1U << 6,
        FLAG_ROW_WEIGHT = 1U << 7,
        FLAG_START = 1U << 8,
        FLAG_STOP = 1U << 9
    };
    const unsigned int required_flags =
        FLAG_SEED | FLAG_DOMAIN | FLAG_INSTANCE_ID | FLAG_N | FLAG_Q |
        FLAG_KIND | FLAG_START | FLAG_STOP;
    struct options options;
    const char *alphabet_text = NULL;
    unsigned int flags = 0U;
    int index;
    int status;

    (void)memset(&options, 0, sizeof(options));
    if (argc < 2 || (argc % 2) == 0) {
        return usage_error("flags must each have exactly one value");
    }
    for (index = 1; index < argc; index += 2) {
        const char *flag = argv[index];
        const char *value = argv[index + 1];
        unsigned int current_flag;
        uint64_t parsed;

        if (strcmp(flag, "--seed") == 0) {
            current_flag = FLAG_SEED;
            if (!parse_seed(value, options.seed)) {
                return usage_error("seed must contain exactly 64 hexadecimal characters");
            }
        } else if (strcmp(flag, "--domain") == 0) {
            current_flag = FLAG_DOMAIN;
            options.domain = value;
            options.domain_len = strlen(value);
            if (options.domain_len == 0U ||
                !valid_utf8((const unsigned char *)value, options.domain_len)) {
                return usage_error("domain must be nonempty valid UTF-8");
            }
        } else if (strcmp(flag, "--instance-id") == 0) {
            current_flag = FLAG_INSTANCE_ID;
            options.instance_id = value;
            options.instance_id_len = strlen(value);
            if (!valid_instance_id(value, options.instance_id_len)) {
                return usage_error("instance ID is not safe ASCII");
            }
        } else if (strcmp(flag, "--n") == 0) {
            current_flag = FLAG_N;
            if (!parse_u64(value, MATRIX_N_MAX, &parsed) || parsed == 0U) {
                return usage_error("n must be an integer from 1 through 4096");
            }
            options.n = (uint32_t)parsed;
        } else if (strcmp(flag, "--q") == 0) {
            current_flag = FLAG_Q;
            if (!parse_u64(value, UINT32_MAX, &parsed) || parsed < 3U) {
                return usage_error("q must be an integer from 3 through UINT32_MAX");
            }
            options.q = (uint32_t)parsed;
        } else if (strcmp(flag, "--kind") == 0) {
            current_flag = FLAG_KIND;
            options.kind = parse_kind(value);
            if (options.kind == KIND_UNSET) {
                return usage_error("unknown matrix kind");
            }
        } else if (strcmp(flag, "--alphabet") == 0) {
            current_flag = FLAG_ALPHABET;
            alphabet_text = value;
        } else if (strcmp(flag, "--row-weight") == 0) {
            current_flag = FLAG_ROW_WEIGHT;
            if (!parse_u64(value, UINT32_MAX, &parsed) || parsed == 0U) {
                return usage_error("row weight must be a positive uint32 integer");
            }
            options.row_weight = (uint32_t)parsed;
        } else if (strcmp(flag, "--start") == 0) {
            current_flag = FLAG_START;
            if (!parse_u64(value, UINT64_MAX, &options.start)) {
                return usage_error("start must be a uint64 integer");
            }
        } else if (strcmp(flag, "--stop") == 0) {
            current_flag = FLAG_STOP;
            if (!parse_u64(value, UINT64_MAX, &options.stop)) {
                return usage_error("stop must be a uint64 integer");
            }
        } else {
            return usage_error("unknown flag");
        }
        if ((flags & current_flag) != 0U) {
            return usage_error("duplicate flag");
        }
        flags |= current_flag;
    }

    if ((flags & required_flags) != required_flags) {
        return usage_error("missing required flag");
    }
    if (options.start > options.stop) {
        return usage_error("start must not exceed stop");
    }
    if (options.kind == KIND_UNIFORM || options.kind == KIND_SPARSE_UNIFORM) {
        if ((flags & FLAG_ALPHABET) != 0U) {
            return usage_error("uniform matrix kinds reject alphabet");
        }
    } else {
        bool exclude_zero = options.kind == KIND_SPARSE_SMALL_ALPHABET;
        if ((flags & FLAG_ALPHABET) == 0U ||
            !parse_alphabet(alphabet_text,
                            options.q,
                            exclude_zero,
                            &options.alphabet,
                            &options.alphabet_len)) {
            return usage_error("small matrix kind requires a valid sorted alphabet");
        }
    }
    if (options.kind == KIND_SPARSE_UNIFORM ||
        options.kind == KIND_SPARSE_SMALL_ALPHABET) {
        if ((flags & FLAG_ROW_WEIGHT) == 0U ||
            options.row_weight > options.n) {
            free(options.alphabet);
            return usage_error("sparse matrix kind requires row weight from 1 through n");
        }
    } else if ((flags & FLAG_ROW_WEIGHT) != 0U) {
        free(options.alphabet);
        return usage_error("dense matrix kinds reject row weight");
    }

    status = materialize(&options);
    free(options.alphabet);
    return status;
}
