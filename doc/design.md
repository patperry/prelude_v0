# Concepts

## Definition

The *null* value is a special object denoting "undefined".

A *type* is a set of values that contains *null*.  For type `T` a *`T` value`*
is a member of `T`. 

A *lexicon* is a set of Unicode character sequences; a member of a lexicon
is called a *name*.

An *attribute* is a (name, type) pair.

A *schema* is a sequence of zero or more attributes with distinct names.

A *record* with schema `s` is either `null` or a value from the product set
formed from the types in `s`.

A *collection* of size `n` is a sequence of `n` objects.

A *table* with schema `s` is collection of records with schema `s`.

A *relation* with schema `s` is a set of records with schema `s` such that no
record is null. Every relation is a table, but a table is only a relation if
its records are unique.

A *dataset* is a set of (name, table) pairs such that all names are
distinct.

A *project* is a set of (name, dataset) pairs such that all names are
distinct.


## Implementation

### Lexicon

The lexicon for all names is set of non-empty character strings of Roman
letters (`A-Z`, `a-z`), Arabic numerals (`0-9`), and the underscore character
(`_`), such that the first character is a Roman letter (not a digit or
underscore).


### Data Types

There are nine *basic* data types, which include the following values in addition
to `null`:

  + `Null`: no values besides `null`

  + `Bool`: logical values `false` and `true`

  + `Int`: integers in the open range `(-2^63, 2^63)`; note that this
    differs from the 64-bit signed integer type used in most programming
    environments in that it includes `null` and excludes the value
    `-2^63 - 1`

  + `Real`: double-precision floating-point values, excluding not-a-number
    (`NaN`) values

  + `Date`: a year-month-day logical calendar date between `0001-01-01`
    and `9999-12-31`

  + `Time`: an hour-minute-second-subsecond time, with the subsecond given as
    microseconds; hour, minute, and second range in 0-23, 0-59, 0-59,
    respectively

  + `DateTime`: a `Date`-`Time` pair

  + `Timestamp`: an absolute point in time, stored to microsecond precision,
    ranging from `0001-01-01 00:00:00 UTC` to `9999-12-31 23:59:59.999999 UTC`

  + `Text`: sequences of Unicode characters

  + `Bytes`: sequences of 8-bit bytes


In addition to the basic data types there are two families of *composite* data
types: arrays and records.


For any type `T`, the array type `Array<T>` is the set of sequences of `T`
values (and `null`).


For zero or more distinct attributes `(f1, T1), ... (fn, Tn)` the record type
`Record<f1 T1, ..., fn Tn>` is the set containing `null` and the set of tuples
`(x1, ..., xn)` with each value `xi` from corresponding type `Ti` for
`i = 1, ..., n`. The number `n` is called the *degree* of the record.
