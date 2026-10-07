import 'package:integration_test/integration_test_driver.dart';

/// Writes build/scroll_perf.json with the frame timing summary.
Future<void> main() => integrationDriver(
  responseDataCallback: (data) async {
    if (data != null) await writeResponseData(data, testOutputFilename: 'scroll_perf');
  },
);
