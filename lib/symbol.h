#ifndef SYMBOL_H
#define SYMBOL_H

typedef struct {
    Text text;
} Symbol;

typedef struct {
    Text text;
    int symbol_id;
} SymbolToken;

typedef struct {
    Symbol *symbols;
    SymbolToken *tokens;
    int symbol_count;
    int symbol_capacity;
    int token_count;
    int token_capacity;
} SymbolSet;

void symbols_init(Context *ctx, SymbolSet *set);
void symbols_deinit(Context *ctx, SymbolSet *set);
void symbols_clear(Context *ctx, SymbolSet *set);

int symbols_add(Context *ctx, SymbolSet *set, const Text *token);
int symbols_get(Context *ctx, const SymbolSet *set, const Text *token);

#endif /* SYMBOL_H */
