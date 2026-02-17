# Code Style & Conventions

## Formatting
- `.clang-format` at repo root (BasedOnStyle: Google, customized)
- Indent: 2 spaces, no tabs
- Column limit: 132
- Braces: Functions on new line, control statements same line (Allman for functions, K&R for blocks)
- Pointer alignment: Right (`char *p`, not `char* p`)

## Naming Conventions
- **Functions**: `tf5_` prefix, snake_case (e.g., `tf5_compute_tag`, `tf5_chain_key`)
- **Types**: `tf5_` prefix, snake_case, `_t` suffix (e.g., `tf5_slot_time_t`, `tf5_buffer_entry_t`)
- **Constants/Macros**: `TF5_` prefix, UPPER_SNAKE_CASE (e.g., `TF5_TESLA_KEY_LEN`, `TF5_VERSION`)
- **Static helpers**: `tf5_tesla_` prefix, snake_case (e.g., `tf5_tesla_slots_since_t0`)

## Logging
- Uses OAI logging subsystem with custom `TF5` log category
- Macros: `LOG_E(TF5, ...)`, `LOG_I(TF5, ...)`, `LOG_D(TF5, ...)`
- Levels: E (error), W (warning), I (info), D (debug), T (trace)

## Include Guards
- `#ifndef TF5_TESLA_H` / `#define TF5_TESLA_H` style

## Conditional Compilation
- All TF5 code wrapped in `#ifdef ENABLE_TF5` (source files start with `#ifdef ENABLE_TF5`)
- Headers use `#ifdef ENABLE_TF5` after include guard

## Documentation Style
- Doxygen-style `/** ... */` for API functions and types
- `/* ... */` block comments for section headers (with `====` separators)
- `//` inline comments for brief explanations

## Test Conventions
- Google Test (C++ `.cpp` files)
- Test files: `test_tf5_tesla_<topic>.cpp`
- Test vectors in `openair3/SECU/tests/tf5_test_vectors.h`
- Each test file has its own `main()` (no `gtest_main`)

## Error Handling
- `tf5_error_t` enum (defined in `tf5_ibs_defs.h`): All recoverable/expected failures (TF5_OK=0, TF5_ERR_*=negative)
- `AssertFatal()`: Unrecoverable system failures (e.g., OpenSSL primitives that should never fail with valid inputs)
- `bool` returns: Verification-only functions (safe packet test, key chain)
- Input validation at function entry with early returns

## General Patterns
- Domain separation prefixes for hash operations (e.g., `TF5_DS_PREFIX_CHAIN_KEY`)
- Buffer sizes defined as named constants
- Thread-local storage used for caching (e.g., MPK caching)
