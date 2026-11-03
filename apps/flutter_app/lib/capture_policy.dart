/// A denied or failed target-side permission check must never open OS capture.
bool captureAuthorized(void Function() targetViewCheck) {
  try {
    targetViewCheck();
    return true;
  } catch (_) {
    return false;
  }
}
