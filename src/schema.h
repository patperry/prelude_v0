#ifndef SCHEMA_H
#define SCHEMA_H

typedef int name_id;
typedef int datatype_id;

enum data_type {
    DATA_ANY = -1,
    DATA_NULL = 0,
    DATA_BOOLEAN,
    DATA_INTEGER,
    DATA_REAL,
    DATA_DATE,
    DATA_TIME,
    DATA_DATETIME,
    DATA_TIMESTAMP,
    DATA_TEXT,
    DATA_BYTES,
    DATA_ARRAY,
    DATA_RECORD
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
