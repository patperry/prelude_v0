#ifndef SCHEMA_H
#define SCHEMA_H

typedef int datatype_id;

enum datatype_kind {
    DATATYPE_ANY = -1,
    DATATYPE_NULL = 0,
    DATATYPE_BOOLEAN,
    DATATYPE_INTEGER,
    DATATYPE_REAL,
    DATATYPE_DATE,
    DATATYPE_TIME,
    DATATYPE_DATETIME,
    DATATYPE_TIMESTAMP,
    DATATYPE_TEXT,
    DATATYPE_BYTES,
    DATATYPE_ARRAY,
    DATATYPE_RECORD
};

struct datatype_array {
    datatype_id element_type;
};

struct datatype_record {
    datatype_id *field_types;
    name_id *field_names;
    int field_count;
};

struct datatype {
    enum datatype_kind kind;
    union {
		struct datatype_array array;
		struct datatype_record record;
    } meta;
};

typedef struct schema {
    struct datatype *types;
    int type_count;
    int type_capacity;
} schema;

void schema_init(context *ctx, schema *schema);
void schema_destroy(context *ctx, void *schema);
void schema_clear(context *ctx, schema *schema);

#endif /* SCHEMA_H */
