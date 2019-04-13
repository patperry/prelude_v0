#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "buffer.h"


/* Default initial size for nonempty dynamic arrays. Must be positive. */
#define BUFFER_INIT 32

/* Growth factor for dynamic arrays. Must be greater than 1. */
#define BUFFER_GROW 1.618 /* Golden Ratio, (1 + sqrt(5)) / 2 */


static Error buffer_size(Context *ctx, size_t width, int32_t *pcapacity,
                         int32_t count, int32_t extra);


Error buffer_reserve(Context *ctx, void **pbuf, size_t width,
                     int32_t *pcapacity, int32_t count, int32_t extra)
{
    int32_t old_capacity = *pcapacity;
    if (old_capacity < 0) {
        old_capacity = 0;
    }

    int32_t new_capacity = old_capacity;
    Error err = buffer_size(ctx, width, &new_capacity, count, extra);
    if (err) {
        return err;
    }

    size_t old_size = (size_t)old_capacity * width;
    size_t new_size = (size_t)new_capacity * width;

    void *buf = context_realloc(ctx, *pbuf, old_size, new_size);
    if (!buf) {
        return context_error(ctx);
    }

    *pbuf = buf;
    *pcapacity = new_capacity;
    return ERROR_NONE;
}


Error buffer_size(Context *ctx, size_t width, int32_t *pcapacity,
                  int32_t count, int32_t extra)
{
    assert(width > 0);
    assert(count >= 0);
    assert((size_t)count <= SIZE_MAX / width);

    if (extra <= 0) {
        return ERROR_NONE;
    }

    if (extra > INT32_MAX - count) {
        return context_panic(ctx, ERROR_OVERFLOW, "required number of elements"
                             " exceeds maximum (%"PRId32")", INT32_MAX);
    }

    int32_t capacity_min = count + extra;
    if ((size_t)capacity_min > SIZE_MAX / width) {
        return context_panic(ctx, ERROR_OVERFLOW, "required number of elements"
                             " exceeds maximum (%zu)", SIZE_MAX / width);
    }

    int32_t capacity = *pcapacity;

    if (capacity < 0) {
        capacity = 0;
    }

    assert((size_t)capacity <= SIZE_MAX / width);

	assert(BUFFER_INIT > 0);
	assert(BUFFER_GROW > 1);

	if (capacity < BUFFER_INIT && capacity_min > 0) {
		capacity = BUFFER_INIT;
	}

	while (capacity < capacity_min) {
		double n = BUFFER_GROW * capacity;
        if (n > INT32_MAX) {
            n = INT32_MAX;
        }
		if (n > SIZE_MAX / width) {
			capacity = SIZE_MAX / width;
		} else {
			capacity = (int32_t)n;
		}
	}

    *pcapacity = capacity;
    return ERROR_NONE;
}

