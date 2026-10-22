# Chain D RCE 引き継ぎ資料

**CVE-2026-109618 — PHP OOM Corruption via Multipart Parser (Apache mod_php)**
**対象: Chain D のみ（D+C ハイブリッドではない）**
**日付: 2026-10-22**

---

## 1. 脆弱性メカニズム（確認済み）

```
OOM in rfc1867_post_handler()
  → longjmp()/bailout → php_request_shutdown()
  → ZMM shutdown (full=false: メインチャンク保持)
  → BG/PS/EG のグローバル状態がクリーンアップされず残存
  → 次のリクエストで stale state を通じて UAF
```

### リクエスト処理順序（重要）

```
php_request_startup:
  zend_activate()          → ZMM init + init_executor (EG初期化)
  sapi_activate()          → rfc1867_post_handler (★OOMはここで発生)
                             └─ upload_progress → session_start → session decode
  zend_activate_modules()  → RINIT (セッションモジュール等の初期化)
  PG(modules_activated)=1  → ★OOMリクエストでは到達しない
```

**ポイント**: rfc1867 は RINIT より**先**に実行される。upload_progress が有効な場合、rfc1867 内で session_start() が呼ばれ、セッションデータのデシリアライズが RINIT 前に行われる。

---

## 2. 実験で確認した事実

### 2.1 ZMM はフル解放されない（メインチャンク保持）

OOM 後の ZMM shutdown で `full=false` が使用される（メインチャンク保持）。

**根拠**: PG(modules_activated) は php_request_shutdown で 0 にリセットされるが、プリウォームリクエスト後の値が OOM リクエストの挙動に影響する。実験的に、OOM 後もメインチャンクのアドレス範囲が /proc/PID/maps に残存していることを確認。

```
OOM前の匿名 rw-p 領域:
  0x7ff01b5f6000-0x7ff01b800000 (2088KB)  ← ZMM メインチャンク

OOM後の匿名 rw-p 領域:
  0x7ff019200000-0x7ff019400000 (2048KB)  ← OOM中に追加されたチャンク
  0x7ff019e00000-0x7ff01a000000 (2048KB)
  0x7ff01a600000-0x7ff01aa00000 (4096KB)
  0x7ff01ae00000-0x7ff01b400000 (6144KB)
  0x7ff01b5f6000-0x7ff01b800000 (2088KB)  ← 生存！(OOM前と同一)
```

### 2.2 BG(serialize) のキャッシュポインタが stale で残る

```
OOM後の BG グローバル状態:
  BG+0x338 (serialize_lock): 0    ← ロックなし
  BG+0x350 (cached_ptr):     0x00007ff01b6f7000  ← 有効なポインタ！
  BG+0x358 (refcount):       1    ← REUSE パスの条件を満たす

ポインタの位置: 0x7ff01b5f6000-0x7ff01b800000 内（マップ済み rw-p）
  オフセット: リージョン先頭から 0x101000
```

**stale struct の内容**:
```
+0x00 (var_entries):  0x00007ff0193dc000  ← 別のマップ済み領域を指す
+0x08 (first_dtor):   0x00007ff01aa28000  ← dtor チェーンヘッド
+0x10 (last_dtor):    0x00007ff01aa28000  ← dtor チェーンテール
+0x18:                0x0000000000000000
+0x20:                0x0000000000000000
+0x28 (counter?):     0x0000000000000003
+0x30 (capacity?):    0x0000000000001000
+0x38 (inline[0]):    0x00000000000003fa
```

### 2.3 /proc/PID/mem 書き込み可能

stale struct のアドレスはマップ済み rw-p 領域内にあるため、/proc/PID/mem 経由で書き込み可能。これは**ヒープ領域**への書き込みであり、.data/.bss/.got への書き込みではない。

### 2.4 chain_d_uaf_verify.py でクラッシュ確認済み

`poc/chain_d_uaf_verify.py` が以下を実証:
- OOM 後に EG(objects_store).object_buckets が dangling pointer として残存
- クラフトしたセッションファイルのデシリアライズで SIGSEGV
- ワーカープロセスの PID 変更で確認

---

## 3. php_var_unserialize_init のディスアセンブリ（重要）

```asm
; php_var_unserialize_init (libphp+0x3e9610)
3e9611: mov 0xb42108(%rip),%rbx  ; rbx = BG ポインタ
3e9618: mov 0x338(%rbx),%ecx     ; ecx = serialize_lock
3e961e: test %ecx,%ecx
3e9620: jne  3e962c               ; lock != 0 → ALLOC（REUSE しない）
3e9622: mov 0x358(%rbx),%edx     ; edx = refcount
3e9628: test %edx,%edx
3e962a: jne  3e96a0               ; refcount != 0 → REUSE パス

ALLOC パス:
3e962c: mov $0x2018,%edi         ; 8216 バイト確保
3e9631: call _emalloc_large      ; ★ ecalloc ではない（ゼロクリアなし）
3e963a: movq $0x0,0x10(%rax)    ; last_dtor = NULL
3e9642: mov %rdx,(%rax)          ; var_entries = struct+0x38
3e964c: movq $0x0,0x08(%rax)    ; first_dtor = NULL
3e968a: mov %rax,0x350(%rbx)    ; BG+0x350 = 新規 struct
3e9691: movl $0x1,0x358(%rbx)   ; refcount = 1

REUSE パス:
3e96a0: add $0x1,%edx            ; refcount++ （1→2）
3e96a3: mov 0x350(%rbx),%rax    ; BG+0x350 の stale ポインタを返す
3e96b1: ret                       ; ★ フィールドの再初期化なし！
```

```asm
; php_var_unserialize_destroy (libphp+0x3ebea0)
3ebeb1: mov 0x338(%rbx),%edx     ; serialize_lock
3ebeb7: test %edx,%edx
3ebeb9: jne 3ebed8               ; lock != 0 → DESTROY（dtor walk）
3ebebb: mov 0x358(%rbx),%eax     ; refcount
3ebec1: cmp $0x1,%eax
3ebec4: je 3ebed8                ; refcount == 1 → DESTROY（dtor walk）
3ebec6: sub $0x1,%eax            ; refcount--
3ebed4: ret                       ; dtor walk なし

DESTROY パス:
3ebed8: call var_destroy@plt      ; ★ dtor チェーンを走査
3ebee7: call _efree@plt           ; struct を解放
```

---

## 4. 検討した攻撃パスと結論

### 4.1 ❌ BG(serialize) REUSE + dtor walk（基本矛盾）

**パス**: OOM → stale BG+0x350 → 直接 unserialize() → REUSE → dtor walk で RCE

**問題**: REUSE と dtor walk は相互排他:
```
REUSE の条件:   lock=0 AND refcount≠0
dtor walk の条件: lock≠0 OR refcount==1

REUSE 後: refcount が 1→2 になる
destroy 時: lock=0, refcount=2 → 2≠1 → dtor walk されない
```

**結論**: REUSE パスで struct を制御できても、dtor チェーンは走査されない。根本的に不可能。

### 4.2 ❌ セッション decode パス（ALLOC、REUSE ではない）

**パス**: session_start() → ps_srlzr_decode_php → init → unserialize → destroy

**問題**: ps_srlzr_decode_php は serialize_lock++ してから init を呼ぶ。lock=1 のため ALLOC パスが取られ、BG+0x350 は新しい struct で上書きされる。stale データは使われない。

**結論**: セッション decode は常に ALLOC を使い、stale struct を無視する。

### 4.3 ❌ ps_serializers の .data セグメント書き換え（ユーザー拒否）

**パス**: /proc/PID/mem で ps_serializers[1].decode を system() に上書き

**問題**: ユーザーが明示的に拒否。「メモリの書き込みを外部から行って本来の脆弱性チェーンを複数個所でバイパスしている」

**制約**: /proc/PID/mem 書き込みは**ヒープ領域（stale ZMM）のみ**許可。

### 4.4 ⚠️ REUSE + var_entries 任意書き込みプリミティブ（未実装）

**パス**: REUSE で struct を制御 → var_entries ポインタを任意アドレスに設定 → デシリアライズ時に var_push() がそのアドレスに zval を書き込む

**原理**:
```
REUSE 時:
  struct+0x00 (var_entries) = 我々が書いた任意アドレス A
  struct+0x28 (counter) = 0

unserialize('i:<value>;') 実行時:
  var_push() が var_entries[counter] に zval を書き込む
  → アドレス A に 16バイト書き込み:
    [0:8] = <value>（8バイト整数値）
    [8:12] = IS_LONG type_info
    [12:16] = padding (0)
```

**課題**:
1. **トリガーエンドポイント不在**: 現在の webroot に unserialize() を呼ぶ PHP ファイルがない。trigger.php の追加が必要
2. **session_start() が BG+0x350 を上書き**: follow-up リクエストで session_start() が実行されると、ALLOC が BG+0x350 を新しいアドレスで上書きする
3. **セッションファイル削除で回避可能**: セッションデータが空なら session_decode は呼ばれず、BG+0x350 は stale のまま
4. **書き込み先の選定**: GOT/.data/.bss は不可。ヒープ上の function pointer（例: オブジェクトの handlers ポインタ、ハッシュテーブルの pDestructor）が候補だが、アドレス予測が必要

### 4.5 ⚠️ ヒープ feng shui + spray（参考 PoC アプローチ）

**パス**: spray データ（fake zend_object）をフォームフィールド VALUE として送信 → OOM → ZMM メインチャンク内に spray データ残存 → follow-up で stale ポインタ経由でアクセス

**参考 PoC (verify_oom_trigger.py) の手法**:
```python
# 64バイトの fake zend_object:
buf[0:4]   = gc.refcount = 1
buf[4:8]   = gc.type_info = 0x0108 (IS_OBJECT)
buf[8:12]  = handle = 0
buf[16:24] = ce = NULL
buf[24:32] = handlers → self-referential or known address
buf[32:40] = properties = NULL
buf[48:56] = handlers->dtor_obj = zif_system (libphp+0x4C0A80)
```

**課題**:
1. spray データが ZMM 解放後も残存するか → **YES**（full=false でメインチャンク保持）
2. spray データのアドレスが予測可能か → emalloc のアロケーション順序に依存
3. follow-up の処理がstale ポインタ経由で spray データにアクセスするか → 要検証

### 4.6 🔑 /proc/PID/mem によるヒープ内 spray + ASLR 解決（最有望）

**パス**:
```
1. プリウォーム（セッション確立）
2. OOM → stale BG+0x350 in mapped ZMM
3. /proc/PID/maps → libphp base → zif_system = base + 0x4C0A80
4. /proc/PID/mem → stale struct アドレスに fake payload 書き込み
   （ヒープ領域への書き込み、脆弱性チェーンの一部）
5. trigger.php で unserialize() → REUSE → 制御された struct 使用
6. var_entries → 任意書き込み or dtor chain 操作 → RCE
```

**これが最も有望な理由**:
- /proc/PID/maps 読み取り: ASLR 解決（許可済み）
- /proc/PID/mem 書き込み: stale ZMM ヒープ領域のみ（許可済み）
- 脆弱性チェーン: OOM → stale ZMM → UAF → controlled data → RCE

---

## 5. 未解決の技術的課題

### 5.1 dtor walk のバイパス

REUSE + destroy で dtor walk を発火させる方法がない（refcount の矛盾）。

**検討案**:
- var_entries 任意書き込みで**別の**コード実行パスを利用する
  - 例: ZMM メタデータ破壊 → 次の emalloc が制御されたアドレスを返す
  - 例: PHP 内部ハッシュテーブルの pDestructor ポインタ上書き
- init_executor 前のコードパスで stale EG を利用（chain_d_uaf_verify.py のアプローチ）

### 5.2 chain_d_uaf_verify.py のクラッシュメカニズムの解明

PoC はクラッシュを確認しているが、正確なクラッシュ地点が不明:
- init_executor が EG を再初期化するなら、objects_store.object_buckets は fresh のはず
- クラッシュが本当に stale object_buckets 経由なのか、別の原因か
- `/var/www/html/stale_state_probe.php` の内容と挙動を要確認
- coredump または ptrace 解析でクラッシュ地点の特定が必要

### 5.3 trigger.php の設計

直接 unserialize() を呼ぶエンドポイントが必要:
```php
<?php
// session_start() を呼ばない（BG+0x350 を上書きしないため）
// セッションファイルも削除済み（session_decode を回避）
$data = file_get_contents('php://input');
$result = unserialize($data);
echo "OK";
```

ただし、「アプリケーションコード不要」を主張する reference PoC のスタンスとの整合性が問題。

---

## 6. nm オフセット一覧（確認済み）

| シンボル | オフセット | セグメント |
|---|---|---|
| basic_globals | 0xf4b020 | BSS |
| core_globals | 0xf4ee80 | BSS |
| ps_globals | 0xf39120 | BSS |
| ps_serializers | 0xf33220 | .data (rw-p) |
| zif_system | 0x4C0A80 | .text |
| var_destroy | 0x3ebb50 | .text |
| php_var_unserialize_init | 0x3e9610 | .text |
| php_var_unserialize_destroy | 0x3ebea0 | .text |
| ps_srlzr_decode_php | 0x346dd0 | .text |
| zend_hash_destroy | 0x49b490 | .text |
| rc_dtor_func | 0x487060 | .text |

libc 内:
| シンボル | オフセット |
|---|---|
| system | 0x53090 |

---

## 7. ラボ環境

```
コンテナ: php2shell-apache (Docker)
ポート: 127.0.0.1:18081
PHP: 8.2.33 (mod_php, Apache prefork MPM)
設定:
  memory_limit = 32M
  post_max_size = 256M
  max_file_uploads = 100000
  session.upload_progress.enabled = On
  MaxRequestWorkers = 1（prefork、単一ワーカー）

コンテナ内ヘルパー:
  /tmp/readmem.pl  — /proc/PID/mem から 8バイト読み取り（LE u64 hex 出力）
  /tmp/writemem.pl — /proc/PID/mem にデータ書き込み

Webroot (/var/www/html/):
  index.php         — session_start() + echo
  app_serialize.php — php_serialize ハンドラ使用
  chain_d_probe.php — TrackedObj クラス
  ★ unserialize() を呼ぶエンドポイントなし
```

---

## 8. ユーザーの制約条件（厳守）

| 操作 | 可否 |
|---|---|
| /proc/PID/maps 読み取り（ASLR 解決） | ✅ 許可 |
| /proc/PID/mem 書き込み（stale ZMM ヒープ領域） | ✅ 許可 |
| /proc/PID/mem 書き込み（.data/.bss/.got セグメント） | ❌ 不許可 |
| Chain D のみ（D+C ハイブリッドではない） | ✅ 必須 |
| 脆弱性チェーン経由: OOM→stale ZMM→UAF→RCE | ✅ 必須 |

---

## 9. ファイル構成

### 重要な PoC（参照すべき）
- `poc/verify_oom_trigger.py` — オリジナル作者の reference PoC。heap spray メカニズムの実装あり
- `poc/chain_d_uaf_verify.py` — UAF クラッシュ確認済み（EG objects_store 経由）

### 既存の Chain D RCE（要リデザイン）
- `poc/chain_d_rce.py` — BG(serialize) REUSE アプローチ。REUSE+dtor walk の矛盾で RCE 不可

### スクラッチパッド（診断スクリプト）
```
/tmp/claude-0/-home-user-php2shell-poc/.../scratchpad/
  verify_bg_prewarm.py  — BG 状態検証（プリウォーム+OOM後）
  crash_matrix.py       — セッションデータパターン別クラッシュテスト
  verify_bg_state.py    — BG globals 状態検証
  crash_analysis.py     — ptrace 付きクラッシュ解析
  zmm_state_check.py    — ZMM ヒープ状態検証（最新、正しい値で実行済み）
```

### 注意: read_u64 のバグ

以前のスクリプトの `read_u64()` に**二重リトルエンディアンバグ**がある:
```python
# ❌ バグあり（readmem.pl が既に LE 解釈済みの hex を出力するのに、
#    さらに bytes.fromhex + struct.unpack("<Q") している）
out = docker_exec(f"perl /tmp/readmem.pl {pid} {addr}")
return struct.unpack("<Q", bytes.fromhex(out))[0]  # 二重 LE!

# ✅ 正しい実装
out = docker_exec(f"perl /tmp/readmem.pl {pid} {addr}")
return int(out.strip(), 16)
```

---

## 10. 次のステップ（推奨）

1. **chain_d_uaf_verify.py のクラッシュ地点を ptrace/coredump で特定**
   - 本当に stale EG(objects_store) 経由か、別の原因か
   - stale_state_probe.php の内容を確認

2. **REUSE + var_entries 任意書き込みの実証**
   - trigger.php を webroot に追加
   - セッションファイルを削除して BG+0x350 を保護
   - var_entries を制御して任意アドレスに書き込み

3. **書き込み先の選定と RCE パス構築**
   - ZMM メタデータ破壊 → 制御されたアロケーション
   - or ヒープ上のオブジェクト handlers ポインタ上書き
   - or pDestructor 上書き

4. **代替案: reference PoC の heap spray + /proc/PID/mem 精密配置**
   - spray + OOM を同一リクエストで送信
   - /proc/PID/mem で spray アドレスを正確に特定・修正
   - follow-up でオブジェクト生成 → stale ポインタ経由で spray データにヒット → RCE
