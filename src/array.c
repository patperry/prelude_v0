#include <assert.h>
#include <inttypes.h>

#include "prelude.h"


/* Default initial size for nonempty dynamic arrays. Must be positive. */
#define ARRAY_INIT 32

/* Growth factor for dynamic arrays. Must be greater than 1. */
#define ARRAY_GROW 1.618 /* Golden Ratio, (1 + sqrt(5)) / 2 */


static int32_t array_size(Context *ctx, size_t width, int32_t capacity,
                          int32_t count, int32_t extra, Error *perr);


void array_reserve(Context *ctx, void **pbase, size_t width,
                   int32_t *pcapacity, int32_t count, int32_t extra,
                   Error *perr)
{
    int32_t old_capacity = *pcapacity;
    if (old_capacity < 0) {
        old_capacity = 0;
    }

    int32_t new_capacity = array_size(ctx, width, old_capacity, count, extra,
                                      perr);
    if (*perr) {
        return;
    }

    size_t old_size = (size_t)old_capacity * width;
    size_t new_size = (size_t)new_capacity * width;

    void *base = memory_realloc(ctx, *pbase, old_size, new_size);
    if (!base) {
        *perr = context_error(ctx);
    } else {
        *pbase = base;
        *pcapacity = new_capacity;
    }
}


int32_t array_size(Context *ctx, size_t width, int32_t capacity,
                   int32_t count, int32_t extra, Error *perr)
{
    assert(width > 0);
    assert(count >= 0);
    assert((size_t)count <= SIZE_MAX / width);

    if (extra <= 0) {
        return capacity;
    }

    if (extra > INT32_MAX - count) {
        *perr = context_panic(ctx, ERROR_OVERFLOW, "required number of elements"
                              " exceeds maximum (%"PRId32")", INT32_MAX);
        return -1;
    }

    int32_t capacity_min = count + extra;
    if ((size_t)capacity_min > SIZE_MAX / width) {
        return context_panic(ctx, ERROR_OVERFLOW, "required number of elements"
                             " exceeds maximum (%zu)", SIZE_MAX / width);
    }

    if (capacity < 0) {
        capacity = 0;
    }

    assert((size_t)capacity <= SIZE_MAX / width);

	assert(ARRAY_INIT > 0);
	assert(ARRAY_GROW > 1);

	if (capacity < ARRAY_INIT && capacity_min > 0) {
		capacity = ARRAY_INIT;
	}

	while (capacity < capacity_min) {
		double n = ARRAY_GROW * capacity;
        if (n > INT32_MAX) {
            n = INT32_MAX;
        }
		if (n > SIZE_MAX / width) {
			capacity = SIZE_MAX / width;
		} else {
			capacity = (int32_t)n;
		}
	}

    return capacity;
}
