const reconnectMaxAttempts = 14; // 1+2+4+8+16 then 30s each: about 5 minutes

/// Delay before retry [attempt] (0-based): 1s, 2s, 4s... capped at 30s.
/// Null means give up.
Duration? reconnectDelay(int attempt) {
  if (attempt < 0 || attempt >= reconnectMaxAttempts) return null;
  return Duration(seconds: attempt >= 5 ? 30 : 1 << attempt);
}
