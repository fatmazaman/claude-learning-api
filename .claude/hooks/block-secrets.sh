#!/usr/bin/env bash
# PreToolUse hook: block reading or editing .env files and anything under secrets/.
#
# Input:  the tool call as JSON on stdin (tool_name, tool_input).
# Output: exit 0 = allow; exit 2 = block, and stderr is shown to Claude as the reason.
# Any other non-zero exit would NOT block the tool, so every failure path below exits 2.

block() {
	echo "Blocked by .claude/hooks/block-secrets.sh: $1 Do not read or edit .env files or anything under secrets/. If you need a variable's name or shape, ask the user or use .env.example." >&2
	exit 2
}

command -v jq >/dev/null 2>&1 || block "jq is not installed, so this hook cannot check the request (failing closed)."

input=$(cat)
tool=$(printf '%s' "$input" | jq -r '.tool_name // empty') || block "could not parse the hook input (failing closed)."
[ -n "$tool" ] || block "hook input had no tool_name (failing closed)."

# True if a path names a secret: .env, .env.<anything> (except .env.example/.sample), or secrets/.
# mode "path" (file tools): a path ending in secrets counts, since Grep/Glob can walk the directory.
# mode "word" (Bash): a bare word "secrets" is just prose (a commit message, say), so it needs a
# following slash, as in secrets/key.
is_secret_path() {
	local p=$1 mode=$2 base=${1##*/}
	case "$base" in
	.env.example | .env.sample) ;;
	.env | .env.*) return 0 ;;
	esac
	if [ "$mode" = word ]; then
		case "/$p" in
		*/secrets/*) return 0 ;;
		esac
	else
		case "/$p/" in
		*/secrets/*) return 0 ;;
		esac
	fi
	return 1
}

# Collect every path-like string the tool call refers to.
mode=path
case "$tool" in
Read | Edit | Write | NotebookEdit)
	candidates=$(printf '%s' "$input" | jq -r '[.tool_input.file_path, .tool_input.notebook_path] | .[] | select(. != null)')
	;;
Grep | Glob)
	candidates=$(printf '%s' "$input" | jq -r '[.tool_input.path, .tool_input.pattern, .tool_input.glob] | .[] | select(. != null)')
	;;
Bash)
	# Best effort: split the command into words and test each one. This catches `cat .env`
	# and `grep x secrets/key`, but not indirection such as `cat $(echo .e)nv`. It also blocks a
	# command that merely mentions `.env` in text (e.g. a commit message); use `git commit -F file`.
	mode=word
	candidates=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' | tr ' \t;|&<>=()"'"'"'`' '\n')
	;;
*)
	exit 0
	;;
esac

while IFS= read -r candidate; do
	[ -n "$candidate" ] || continue
	if is_secret_path "$candidate" "$mode"; then
		block "'$candidate' is a protected secrets path (tool: $tool)."
	fi
done <<<"$candidates"

exit 0
