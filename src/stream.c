#include "prelude.h"


void read_init(Context *ctx, Read *req, Stream *stream,
               void *buffer, int length)
{
    (stream->type->read_init)(ctx, req, stream, buffer, length);
}


void read_reset(Context *ctx, Read *req, void *buffer, int length)
{
    (((Stream *)req->stream)->type->read_reset)(ctx, req, buffer, length);
}


void read_deinit(Context *ctx, Read *req)
{
    if (!req->stream)
        return;
    (((Stream *)req->stream)->type->read_deinit)(ctx, req);
}
