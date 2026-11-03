/// Async continuations may mutate only the exact session that started them.
bool ownsSession<T>(int current, int started, T? active, T expected) =>
    current == started && identical(active, expected);
