// Disable LeakSanitizer at build time (leaks are not the bug class this fleet
// fuzzes for); ASan and UBSan stay fully active. Linked into every fuzz and
// -standalone binary by mayhem/build.sh.
int __lsan_is_turned_off(void) { return 1; }
