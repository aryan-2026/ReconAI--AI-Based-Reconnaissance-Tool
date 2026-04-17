"""
ReconAI - Tool Executor
Async subprocess runner for all recon tools.
Handles availability checks, retries, timeouts, and logging.
"""
import asyncio
import subprocess
import shutil
import os
from pathlib import Path
from typing import List, Optional, Dict
from utils.logger import log, info, warn, error, success


class ToolExecutor:
    """Manages async/sync execution of external recon tools."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._available_tools: Dict[str, bool] = {}
        # Extend PATH to include common Go tool locations
        self._extend_path()

    def _extend_path(self):
        """Add common Go binary directories to PATH so tools are found."""
        go_paths = [
            os.path.expanduser("~/go/bin"),
            "/usr/local/go/bin",
            os.path.expanduser("~/.local/bin"),
        ]
        current_path = os.environ.get("PATH", "")
        additions = [p for p in go_paths if p not in current_path and os.path.isdir(p)]
        if additions:
            os.environ["PATH"] = ":".join(additions) + ":" + current_path

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed and available in PATH."""
        if tool_name in self._available_tools:
            return self._available_tools[tool_name]
        available = shutil.which(tool_name) is not None
        self._available_tools[tool_name] = available
        if not available:
            warn(f"Tool not found: [bold]{tool_name}[/bold] (skipping)")
        return available

    def check_all_tools(self, tools: List[str]) -> Dict[str, bool]:
        return {t: self.check_tool(t) for t in tools}

    async def run_async(
        self,
        cmd: List[str],
        timeout: int = 300,
        output_file: Optional[Path] = None,
        stdin_data: Optional[str] = None,
    ) -> Optional[str]:
        """
        Run a command asynchronously.
        Returns stdout as string, or None on failure.
        Streams stderr to warn log in real time.
        """
        cmd_str = " ".join(str(c) for c in cmd)
        display  = cmd_str[:120] + ("..." if len(cmd_str) > 120 else "")
        info(f"Running: [dim]{display}[/dim]")

        try:
            stdin_pipe = asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL

            proc = await asyncio.create_subprocess_exec(
                *[str(c) for c in cmd],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=stdin_pipe,
            )

            stdin_bytes = stdin_data.encode() if stdin_data else None
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=timeout
            )

            stdout_str = stdout.decode("utf-8", errors="ignore").strip()
            stderr_str = stderr.decode("utf-8", errors="ignore").strip()

            # Only surface stderr on non-zero exit AND if it's meaningful
            if proc.returncode != 0 and stderr_str:
                # Filter out purely informational stderr lines common to recon tools
                noisy = any(kw in stderr_str.lower() for kw in [
                    "warn", "info", "[inf", "[wrn", "enumerating", "loading",
                    "using", "version", "started", "found"
                ])
                if not noisy:
                    warn(f"Tool stderr [{cmd[0]}]: {stderr_str[:300]}")

            if output_file and stdout_str:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(stdout_str)

            return stdout_str or None

        except asyncio.TimeoutError:
            error(f"Timed out after {timeout}s: {cmd[0]}")
            try:
                proc.kill()
            except Exception:
                pass
            return None
        except FileNotFoundError:
            error(f"Binary not found: {cmd[0]}")
            return None
        except Exception as e:
            error(f"Execution failed [{cmd[0]}]: {e}")
            return None

    def run_sync(
        self,
        cmd: List[str],
        timeout: int = 300,
        output_file: Optional[Path] = None,
    ) -> Optional[str]:
        """Synchronous version for non-async contexts."""
        cmd_str = " ".join(str(c) for c in cmd)
        info(f"Running (sync): [dim]{cmd_str[:100]}[/dim]")
        try:
            result = subprocess.run(
                [str(c) for c in cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout.strip()
            if output_file and output:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(output)
            return output or None
        except subprocess.TimeoutExpired:
            error(f"Timed out: {cmd[0]}")
            return None
        except FileNotFoundError:
            error(f"Not found: {cmd[0]}")
            return None
        except Exception as e:
            error(f"Failed [{cmd[0]}]: {e}")
            return None

    async def run_parallel(self, tasks: List[Dict]) -> Dict[str, Optional[str]]:
        """
        Run multiple tool commands in parallel.
        tasks = [{"name": str, "cmd": list, "timeout": int, "output_file": Path}, ...]
        Returns dict of name -> stdout string.
        """
        info(f"Launching {len(tasks)} tools in parallel...")

        async def run_one(task):
            return task["name"], await self.run_async(
                task["cmd"],
                timeout=task.get("timeout", 300),
                output_file=task.get("output_file"),
            )

        results = await asyncio.gather(*[run_one(t) for t in tasks])
        return dict(results)

    def save_results(self, filename: str, lines: List[str]) -> Path:
        """Deduplicate, sort and save a list of strings to the output directory."""
        path  = self.output_dir / filename
        unique = sorted(set(l.strip() for l in lines if l.strip()))
        path.write_text("\n".join(unique))
        success(f"Saved {len(unique)} items → {path.name}")
        return path

    def load_results(self, filename: str) -> List[str]:
        path = self.output_dir / filename
        if path.exists() and path.stat().st_size > 0:
            return [l.strip() for l in path.read_text().splitlines() if l.strip()]
        return []

    def merge_and_save(self, output_filename: str, *input_strings: Optional[str]) -> List[str]:
        """Merge multiple raw tool outputs, deduplicate and save."""
        all_items: List[str] = []
        for raw in input_strings:
            if raw:
                all_items.extend(raw.splitlines())
        self.save_results(output_filename, all_items)
        return self.load_results(output_filename)

    def append_results(self, filename: str, new_lines: List[str]) -> Path:
        """Append new lines to an existing results file (deduplicating)."""
        existing = self.load_results(filename)
        combined = existing + new_lines
        return self.save_results(filename, combined)
