import 'dart:io';

import 'package:drift/drift.dart';
import 'package:drift/native.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Local metadata only. Private keys remain in platform secure storage.
class LocalStore {
  LocalStore._(this.db);
  final QueryExecutor db;
  static Future<LocalStore> open() async {
    final folder = await getApplicationSupportDirectory();
    final db = NativeDatabase.createInBackground(
      File(p.join(folder.path, 'remote_link.sqlite')),
    );
    await db.ensureOpen(_StoreUser());
    return LocalStore._(db);
  }

  Future<void> saveDevice(String id) => db
      .runInsert('INSERT OR IGNORE INTO devices (id) VALUES (?)', [id])
      .then((_) {});
  Future<List<String>> devices() async => (await db.runSelect(
    'SELECT id FROM devices ORDER BY id',
    [],
  )).map((row) => row['id'] as String).toList();
  Future<void> audit(String event) => db
      .runInsert('INSERT INTO audit (at, event) VALUES (?, ?)', [
        DateTime.now().toUtc().toIso8601String(),
        event,
      ])
      .then((_) {});
  Future<List<String>> auditEntries() async => (await db.runSelect(
    'SELECT at, event FROM audit ORDER BY id DESC LIMIT 100',
    [],
  )).map((row) => '${row['at']} - ${row['event']}').toList();
  Future<void> close() => db.close();
}

class _StoreUser extends QueryExecutorUser {
  @override
  int get schemaVersion => 1;
  @override
  Future<void> beforeOpen(
    QueryExecutor executor,
    OpeningDetails details,
  ) async {
    await executor.runCustom(
      'CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY NOT NULL)',
      [],
    );
    await executor.runCustom(
      'CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, event TEXT NOT NULL)',
      [],
    );
  }
}
