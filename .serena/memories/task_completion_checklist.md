# Task Completion Checklist

When completing a coding task, verify the following:

## 1. Build Verification
- [ ] Code compiles without warnings: `cmake --build --preset 5gdefault`
- [ ] If tests modified: `cmake --build --preset tf5_tests`

## 2. Test Verification
- [ ] Run relevant tests: `ctest -R tf5 -V` (from `build_test/`)
- [ ] All existing tests pass
- [ ] New functionality has test coverage (add to existing test files or create new)

## 3. Code Quality
- [ ] Follow `tf5_` naming prefix for all new symbols
- [ ] New code wrapped in `#ifdef ENABLE_TF5` where appropriate
- [ ] No security vulnerabilities (buffer overflows, use-after-free, etc.)
- [ ] Use `LOG_E/W/I/D(TF5, ...)` for logging (not printf)

## 4. Documentation Sync
- [ ] If externally observable behavior changed → update `doc-tf5/`
- [ ] New files in `doc-tf5/` linked from `doc-tf5/index.md`

## 5. Formatting
- [ ] Run `clang-format -i` on modified files

## 6. Git
- [ ] Commit author override: "Claude Code"
- [ ] Comments, commit messages, and documentation in English
- [ ] Branch: `tf5`
