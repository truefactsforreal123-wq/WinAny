import 'dart:math' as math;

/// Normalizes a pointer only inside the BoxFit.contain video rectangle.
({double x, double y})? mapVideoPointer(
  double x,
  double y,
  double width,
  double height,
  double videoWidth,
  double videoHeight,
) {
  if (width <= 0 || height <= 0 || videoWidth <= 0 || videoHeight <= 0)
    return null;
  final scale = math.min(width / videoWidth, height / videoHeight);
  final w = videoWidth * scale, h = videoHeight * scale;
  final left = (width - w) / 2, top = (height - h) / 2;
  if (x < left || x > left + w || y < top || y > top + h) return null;
  return (x: (x - left) / w, y: (y - top) / h);
}
