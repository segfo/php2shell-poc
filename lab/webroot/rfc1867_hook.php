<?php
// This script registers a session_set_save_handler that logs when
// session operations occur. By checking the ORDER of operations,
// we can detect if rfc1867 is operating on stale session state.
//
// Key: if open() is called with a session ID that wasn't set by
// session_start() in THIS request, it means rfc1867 is using a
// stale PS(id).

$logfile = "/tmp/session_hook.log";

class SessionHookHandler implements SessionHandlerInterface {
    private $logfile;
    private $request_id;

    public function __construct($logfile) {
        $this->logfile = $logfile;
        $this->request_id = getmypid() . "-" . microtime(true);
    }

    private function log($msg) {
        $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $caller = isset($bt[1]) ? $bt[1]['function'] : 'unknown';
        $line = sprintf("[%s] PID=%d REQ=%s %s (from %s)\n",
            date("H:i:s.u"), getmypid(), $this->request_id, $msg, $caller);
        file_put_contents($this->logfile, $line, FILE_APPEND);
    }

    public function open($path, $name): bool {
        $this->log("OPEN path=$path name=$name");
        return true;
    }

    public function close(): bool {
        $this->log("CLOSE");
        return true;
    }

    public function read($id): string|false {
        $file = "/tmp/sess_$id";
        $data = @file_get_contents($file);
        $this->log("READ id=$id size=" . ($data ? strlen($data) : "MISSING"));
        return $data ?: "";
    }

    public function write($id, $data): bool {
        $file = "/tmp/sess_$id";
        $this->log("WRITE id=$id size=" . strlen($data));
        return (bool)file_put_contents($file, $data);
    }

    public function destroy($id): bool {
        $this->log("DESTROY id=$id");
        @unlink("/tmp/sess_$id");
        return true;
    }

    public function gc($max_lifetime): int|false {
        $this->log("GC max_lifetime=$max_lifetime");
        return 0;
    }
}

// This won't intercept rfc1867's session operations because the handler
// is registered AFTER rfc1867 fires (rfc1867 fires before RINIT).
// But it will show what the PHP script sees.
// To intercept rfc1867, we'd need to register via php.ini session.save_handler.
