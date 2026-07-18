// Disable LeakSanitizer at build time (ASan stays on): leaks are not what this fleet fuzzes for.
extern "C" int __lsan_is_turned_off() { return 1; }
