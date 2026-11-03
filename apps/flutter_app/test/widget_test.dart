import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:remote_link/main.dart';

void main() {
  testWidgets(
    'dashboard starts disconnected and requires explicit connection',
    (tester) async {
      await tester.pumpWidget(const ProviderScope(child: RemoteLinkApp()));
      expect(find.text('Remote Link'), findsOneWidget);
      expect(find.text('Status: Disconnected'), findsOneWidget);
      expect(find.text('Go online'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Request access'),
            )
            .onPressed,
        isNull,
      );
    },
  );
}
