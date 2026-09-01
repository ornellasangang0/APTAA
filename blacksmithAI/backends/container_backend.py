"""Backend qui redirige les opérations fichiers vers le conteneur pentest."""

import base64
import os
import requests


class ContainerBackend:
    """Redirige write_file/read_file vers le conteneur pentest via HTTP."""

    def __init__(self, container_uri: str | None = None):
        self.container_uri = container_uri or os.getenv(
            'container_uri', 'http://localhost:9756/exec'
        )

    def _exec(self, cmd: str, timeout: int = 30) -> dict:
        try:
            response = requests.post(
                self.container_uri,
                json={"cmd": cmd, "timeout": timeout}
            )
            if response.status_code != 200:
                return {"output": "", "error": response.text}
            return response.json()
        except Exception as e:
            return {"output": "", "error": str(e)}

    # ── write ────────────────────────────────────────────────────────────────

    def write(self, path: str, content: str):
        content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        cmd = (
            f"python3 -c \""
            f"import base64, os; "
            f"c = base64.b64decode('{content_b64}').decode('utf-8'); "
            f"os.makedirs(os.path.dirname('{path}') or '.', exist_ok=True); "
            f"open('{path}', 'w').write(c); "
            f"print('ok')\""
        )
        result = self._exec(cmd)
        error = None if "ok" in result.get("output", "") else result.get("error")
        return {"path": path, "error": error}

    async def awrite(self, path: str, content: str):
        return self.write(path, content)

    # ── read ─────────────────────────────────────────────────────────────────

    def read(self, path: str, offset: int = 0, limit: int = 200) -> str:
        cmd = (
            f"python3 -c \""
            f"lines = open('{path}').readlines(); "
            f"print(''.join(lines[{offset}:{offset + limit}]))\""
        )
        result = self._exec(cmd)
        return result.get("output", f"Error reading {path}: {result.get('error')}")

    async def aread(self, path: str, offset: int = 0, limit: int = 200) -> str:
        return self.read(path, offset=offset, limit=limit)

    # ── ls ───────────────────────────────────────────────────────────────────

    def ls_info(self, path: str) -> list[dict]:
        cmd = f"ls -1 {path} 2>/dev/null"
        result = self._exec(cmd)
        files = result.get("output", "").strip().splitlines()
        return [{"path": f"{path.rstrip('/')}/{f}"} for f in files if f]

    async def als_info(self, path: str) -> list[dict]:
        return self.ls_info(path)

    # ── edit ─────────────────────────────────────────────────────────────────

    def edit(self, path: str, old_string: str, new_string: str, *, replace_all: bool = False):
        content = self.read(path, offset=0, limit=99999)
        if old_string not in content:
            return {"path": path, "occurrences": 0, "error": f"String not found in {path}"}
        if replace_all:
            new_content = content.replace(old_string, new_string)
            occurrences = content.count(old_string)
        else:
            new_content = content.replace(old_string, new_string, 1)
            occurrences = 1
        result = self.write(path, new_content)
        return {"path": path, "occurrences": occurrences, "error": result.get("error")}

    async def aedit(self, path: str, old_string: str, new_string: str, *, replace_all: bool = False):
        return self.edit(path, old_string, new_string, replace_all=replace_all)

    # ── glob ─────────────────────────────────────────────────────────────────

    def glob_info(self, pattern: str, path: str = "/") -> list[dict]:
        cmd = f"find {path} -path '{pattern}' 2>/dev/null"
        result = self._exec(cmd)
        files = result.get("output", "").strip().splitlines()
        return [{"path": f} for f in files if f]

    async def aglob_info(self, pattern: str, path: str = "/") -> list[dict]:
        return self.glob_info(pattern, path=path)

    # ── grep ─────────────────────────────────────────────────────────────────

    def grep_raw(self, pattern: str, path: str | None = None, glob: str | None = None):
        search_path = path or "/"
        cmd = f"grep -r '{pattern}' {search_path} 2>/dev/null"
        result = self._exec(cmd)
        return result.get("output", "")

    async def agrep_raw(self, pattern: str, path: str | None = None, glob: str | None = None):
        return self.grep_raw(pattern, path=path, glob=glob)

    # ── download ─────────────────────────────────────────────────────────────

    def download_files(self, paths: list[str]):
        return []

    async def adownload_files(self, paths: list[str]):
        return []
