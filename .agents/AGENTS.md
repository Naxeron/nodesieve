# Workspace Guidelines

## Python Async Concurrency & Network Guidelines

### 1. Async Stream Teardown Safety
- Always wrap `await writer.wait_closed()` in a short `asyncio.wait_for(..., timeout=0.2)` or `try/except` block.
- Never assume peers will send a clean TCP FIN immediately upon `writer.close()`.

### 2. Ephemeral Subprocess Port Binding
- When launching local proxy subprocesses or test servers, never use static port increments (e.g., `port = 10000 + i`).
- Dynamically request an available free port from the OS kernel using socket binding:
  ```python
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('127.0.0.1', 0))
  port = s.getsockname()[1]
  s.close()
  ```
  This prevents `EADDRINUSE` errors caused by socket `TIME_WAIT` states across runs.

### 3. Single-Attempt Cache Pattern for Async Locks
- Never use falsy collection checks (`if not cache:`) inside `asyncio.Lock()` blocks to gate network fetches. If the fetch fails, `cache` remains `{}`/`[]`, forcing every subsequent worker to sequentially retry the failed network call under lock.
- Use explicit boolean flags (`_attempted = True`) and provide pre-populated offline fallback dictionaries:
  ```python
  if not self._attempted:
      async with self._lock:
          if not self._attempted:
              self._attempted = True
              # Attempt fetch with short timeout; fall back to built-in offline defaults
  ```
