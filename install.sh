#!/usr/bin/env sh
# Install the jev-command-classifier skill into local agent harnesses.
#
# Usage:
#   ./install.sh                    # copy into every detected harness
#   ./install.sh --link             # symlink instead of copy (repo stays source of truth)
#   ./install.sh --codex --pi       # only the named harnesses
#   ./install.sh --dest DIR         # copy into DIR/jev-command-classifier
#
# Targets:
#   codex        ${CODEX_HOME:-$HOME/.codex}/skills
#   opencode     ${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills
#   pi           $HOME/.pi/agent/skills
#   commandcode  $HOME/.commandcode/skills

set -eu

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
SKILL_NAME=jev-command-classifier
SKILL_SRC=$REPO_DIR/skills/$SKILL_NAME
MODE=copy
TARGETS=""
DEST=""

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

add_target() {
    case " $TARGETS " in
        *" $1 "*) ;;
        *) TARGETS="$TARGETS $1" ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --link) MODE=link ;;
        --copy) MODE=copy ;;
        --codex) add_target codex ;;
        --opencode) add_target opencode ;;
        --pi) add_target pi ;;
        --commandcode) add_target commandcode ;;
        --all) add_target codex; add_target opencode; add_target pi; add_target commandcode ;;
        --dest)
            shift
            [ $# -gt 0 ] || { echo "install.sh: --dest needs a directory" >&2; exit 2; }
            DEST=$1
            ;;
        -h|--help) usage 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; usage 2 ;;
    esac
    shift
done

[ -f "$SKILL_SRC/SKILL.md" ] || { echo "install.sh: $SKILL_SRC/SKILL.md not found" >&2; exit 1; }

if [ -n "$DEST" ]; then
    TARGETS="dest"
elif [ -z "$TARGETS" ]; then
    add_target codex
    add_target opencode
    add_target pi
    add_target commandcode
fi

resolve_dir() {
    case "$1" in
        codex) printf '%s' "${CODEX_HOME:-$HOME/.codex}/skills" ;;
        opencode) printf '%s' "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills" ;;
        pi) printf '%s' "$HOME/.pi/agent/skills" ;;
        commandcode) printf '%s' "$HOME/.commandcode/skills" ;;
        dest) printf '%s' "$DEST" ;;
    esac
}

for target in $TARGETS; do
    dir=$(resolve_dir "$target")
    parent=$(dirname "$dir")
    if [ ! -d "$parent" ]; then
        echo "skip  $target: $parent does not exist"
        continue
    fi
    mkdir -p "$dir"
    if [ "$MODE" = link ]; then
        ln -sfn "$SKILL_SRC" "$dir/$SKILL_NAME"
        echo "link  $dir/$SKILL_NAME -> $SKILL_SRC"
    else
        rm -rf "$dir/$SKILL_NAME"
        cp -R "$SKILL_SRC" "$dir/"
        find "$dir/$SKILL_NAME" \( -name '__pycache__' -o -name '*.egg-info' \) -type d -prune -exec rm -rf {} +
        echo "copy  $dir/$SKILL_NAME"
    fi
done

echo
echo "Installed. Verify with: python3 \"$SKILL_SRC/scripts/classify_command.py\" --self-test"
