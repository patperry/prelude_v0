#ifndef BUFFER_H
#define BUFFER_H

Error buffer_reserve(Context *ctx, void **pbuf, size_t width,
                     int32_t *pcapacity, int32_t count, int32_t extra);

#endif /* BUFFER_H */
