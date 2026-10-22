# Chain D 主張検証: verify_oom_trigger.py vs パッチ 3584a98

## README主張

> D | OOM corruption → stale EG() | Yes (Pre-auth) | None — any endpoint | mod_php

RCEが可能であると主張している。

---

## パッチ 3584a98 が修正した箇所（事実）

### 修正1: rfc1867.c — OOM時のリソースリーク防止
- `ZEND_HAS_OOM()` フラグ + delayed-OOMメカニズム導入
- fallible allocation関数 (`femalloc`, `safe_ferealloc`) 導入
- 30箇所以上のOOMチェック追加 → `goto fileupload_done` でクリーンアップ
- `safe_php_register_variable()` 等の戻り値を `void` → `bool` に変更
- `php_mime_should_save_hdr()` 追加: Content-Disposition/Content-Type以外のヘッダ保存を停止

**これが修正する脆弱性**: OOMで `longjmp()` → パーサのスタックフレーム放棄 →
`param`, `filename`, `key` 等の `efree()` スキップ → 部分構築された `$_FILES` 配列が
`php_request_shutdown()` で不正にウォークされる。

### 修正2: Zend/zend_execute_API.c — objects_store ダングリングポインタ
```c
// shutdown_executor() の fast shutdown path に追加:
EG(objects_store).object_buckets = NULL;
EG(objects_store).top = 1;
```
加えて `zend_shutdown_executor_values()` (non-fast path) で:
- `EG(user_error_handler)` を UNDEF にリセット
- `EG(exception)` をリセット
- `record_errors`, `num_errors`, `errors` をリセット

**これが修正する脆弱性**: `shutdown_executor()` 後、`object_buckets` が解放済み
ZMMメモリを指したまま残る → 後続でデリファレンスするとUAF。

### 修正3: ext/session/session.c — rfc1867コールバックのstale PS()

#### 3a. `php_rinit_session_globals()` の呼び出しタイミング
```c
case MULTIPART_EVENT_START: {
    // RINIT前に呼ばれるので、セッショングローバルを先にクリア
    php_rinit_session_globals();  // ← 追加
```

#### 3b. `in_rfc1867_update` フラグ + incomplete_classes_only モード
```c
PS(in_rfc1867_update) = true;
// → デシリアライズ時、全オブジェクトを __PHP_Incomplete_Class として処理
// → autoloading, __wakeup(), __unserialize() を一切呼ばない
```

#### 3c. `$_SESSION` の明示的削除
```c
case MULTIPART_EVENT_END:
    zend_string *session_var_name = ZSTR_INIT_LITERAL("_SESSION", 0);
    zend_delete_global_variable(session_var_name);  // ← 追加
    zend_string_release_ex(session_var_name, 0);
```

#### 3d. `php_session_initialize()` の戻り値チェック
```c
// 修正前:
php_session_initialize();
PS(session_status) = php_session_active;  // 無条件でactive

// 修正後:
if (php_session_initialize() == FAILURE || PS(session_status) != php_session_active) {
    PS(in_rfc1867_update) = false;
    return;  // 失敗時は即return
}
```

---

## verify_oom_trigger.py の主張 vs 事実

### 主張1: 「OOMはどのエンドポイントでも発火する」
**検証: TRUE** — multipartパーサは `sapi_activate()` → `sapi_read_post_data()` →
`rfc1867_post_handler()` で動作し、ユーザPHPコード実行前。
パッチがrfc1867.cに30箇所以上のOOMチェックを追加していることがこれを裏付ける。

### 主張2: 「longjmp()でパーサのスタックフレームが放棄される」
**検証: TRUE** — パッチが `ZEND_HAS_OOM()` + delayed-OOMで `longjmp()` 自体を
回避するメカニズムを導入していることから、旧コードでは `longjmp()` がそのまま
発火していたことが確認できる。

### 主張3: 「$_FILES配列が部分構築状態で残る」
**検証: TRUE** — パッチが `safe_php_register_variable()` の戻り値チェック、
`goto fileupload_done` クリーンアップパス、fallible allocationを追加している
ことから、旧コードではこれらが未チェックで部分構築状態になっていた。

### 主張4: 「EG(objects_store).object_buckets がstaleになる」
**検証: TRUE** — パッチが `shutdown_executor()` で明示的に
`object_buckets = NULL; top = 1;` を追加。
我々のUAF検証(`chain_d_uaf_verify.py`)でもsegfaultで実証済み。

### 主張5: 「heap feng shuiでcrashをRCEに変換できる」(verify_oom_trigger.py L152-275)
スクリプトは fake `zend_object` をスプレーし、`handlers->dtor_obj` を
`zif_system` に向ける手法を実装している。

**検証: THEORETICAL（理論上可能だが実証されていない）**

具体的な問題点:
1. **handlers ポインタを self-referential にしている** (L265: `struct.pack_into("<Q", buf, ZOBJ_HANDLERS_OFFSET, 0)`)
   → 絶対アドレスが不明なので NULL を設定。コメントでも「rely on the CRASH verification method」と自認。
2. **スプレーデータがフォームフィールドの値として送信される** (L290-294)
   → `multipart/form-data` の値フィールドはPHPが `zend_string` としてZMMに格納。
   fake zend_object がZMM上の狙った位置に配置される保証がない。
3. **PIE/ASLRバイパスが未実装** — `zif_system` のオフセットはハードコード(L178-182)。
   libphp.soはPIE有効でASLR下では毎回ベースアドレスが変わる。info leakが必要。
4. **verify方法がCRASH判定のみ** (L422-488) — follow-upリクエストへの応答でworkerの
   生死を確認するだけ。実際のコマンド実行証拠は`FILE`メソッドでproof fileを
   チェックするが、それを書き込むgadgetが動作する前提がない。

### 主張6: 「session corruption でデシリアライズクラッシュを起こせる」(--session-corrupt モード)
**検証: PARTIALLY TRUE** — OOM中に`php_session_flush()`が部分構築の`$_SESSION`を
セッションファイルに書き込むことは確認済み。しかし:
- セッションファイルのシリアライズデータは構造的に有効（hash tableの不整合ではなく
  upload_progressデータの途中切断）
- follow-upデシリアライズでPHPエラーは出るが、workerクラッシュには至らない
- パッチの `incomplete_classes_only` モードは、この経路でオブジェクトが
  **ユーザ定義クラスとして復元されない**ことを保証

---

## Chain D RCE成立性の評価

### 攻撃チェーン（理論）
```
1. OOM in rfc1867        → longjmp → ZMM freed
2. objects_store dangling → UAF (segfault実証済み)
3. Heap feng shui        → freed memory を制御
4. Fake zend_object      → handlers->dtor_obj = target_func
5. Object destruction    → vtable dispatch → RCE
```

### ステップごとの成立性

| Step | 状態 | 根拠 |
|------|------|------|
| 1. OOM発火 | **CONFIRMED** | パッチ + 実験 |
| 2. objects_store UAF | **CONFIRMED** | パッチ + segfault実証 |
| 3. Heap制御 | **UNPROVEN** | スプレーは送信可能だが配置制御の証拠なし |
| 4. Fake object配置 | **UNPROVEN** | ZMMのbin size管理で確実な重ね合わせが困難 |
| 5. vtable→RCE | **UNPROVEN** | ASLR/PIEバイパスが必要、info leak未実装 |

### 結論

**Chain D単独でのRCE: 現時点では未実証**

- **DoS (worker crash)**: CONFIRMED — UAFによるsegfaultは確実に起きる
- **UAF primitive**: CONFIRMED — `EG(objects_store).object_buckets` ダングリングポインタ
- **RCE**: UNPROVEN — heap feng shui + ASLR bypass が必要だが `verify_oom_trigger.py` は
  これらを実装していない。`--enable-heapshape` モードはNULLポインタスプレーで
  crashパターン分析のみ。

パッチが以下を全て修正していることは、これらが全て**攻撃可能な状態**であった
ことを示す（開発者が不要な修正を入れることはない）:

1. `object_buckets` の NULL化 → objects_store UAFが存在
2. `php_rinit_session_globals()` → stale PS()が存在
3. `incomplete_classes_only` → オブジェクトデシリアライズが攻撃可能だった
4. `$_SESSION` 削除 → stale session dataがスクリプト層に漏洩
5. delayed-OOM → longjmpによる状態破壊が発生

**パッチの修正範囲の広さ（389ファイル、+10,759行）は、開発者がこれをRCE級の
脆弱性として扱っていることを示す。** CVSS 9.2 Critical の評価もそれを裏付ける。

ただし `verify_oom_trigger.py` 自体は RCEを実証していない。heap shapingコードは
理論的フレームワークとして存在するが、制御されたコード実行の証拠（proof file生成、
コマンド出力取得等）は得られていない。
