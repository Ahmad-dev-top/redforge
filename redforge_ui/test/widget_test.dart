import 'package:flutter_test/flutter_test.dart';
import 'package:redforge_ui/main.dart';

void main() {
  testWidgets('dashboard scaffold builds', (tester) async {
    await tester.pumpWidget(const RedForgeApp());
    expect(find.byType(RedForgeApp), findsOneWidget);
  });
}
