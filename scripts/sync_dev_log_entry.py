from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


def load_dev_log_node(tree: ast.AST) -> ast.Assign:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEV_LOG_ENTRIES":
                    return node
    raise RuntimeError("DEV_LOG_ENTRIES assignment not found in app.py")


def format_dev_log(entries: list[dict[str, object]]) -> str:
    lines = ["DEV_LOG_ENTRIES = ["]
    for entry in sorted(entries, key=lambda item: int(item["pr"])):
        lines.append(f"    {json.dumps(entry, ensure_ascii=False)},")
    lines.append("]")
    return "\n".join(lines)


def normalize_merged_at(raw: str) -> str:
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if "T" in value:
        value = value.replace("T", " ")
    if "+" in value:
        value = value.split("+", 1)[0]
    if value.endswith(" UTC"):
        return value
    return f"{value[:16]} UTC"


def main() -> int:
    parser = argparse.ArgumentParser(description="Ensure a PR has an entry in DEV_LOG_ENTRIES.")
    parser.add_argument("--app-file", default="app.py")
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--pr-title", required=True)
    parser.add_argument("--merged-at", required=True)
    args = parser.parse_args()

    app_path = Path(args.app_file)
    source = app_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    node = load_dev_log_node(tree)
    entries = ast.literal_eval(node.value)

    if any(int(entry.get("pr", -1)) == args.pr_number for entry in entries):
        return 0

    entries.append(
        {
            "pr": args.pr_number,
            "merged_at": normalize_merged_at(args.merged_at),
            "change": f"Merged PR #{args.pr_number}: {args.pr_title}",
            "result": "Development Log entry added automatically by CI.",
            "why": "Guarantee every merged PR is recorded in the in-app Dev Log.",
        }
    )

    replacement = format_dev_log(entries)
    lines = source.splitlines()
    updated_lines = lines[: node.lineno - 1] + [replacement] + lines[node.end_lineno :]
    app_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
