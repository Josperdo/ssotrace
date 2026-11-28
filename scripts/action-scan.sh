#!/bin/sh
# Scans the HAR files tracked in a git repository with `ssotrace scan` and
# fails if any contains a secret. This is the body of the ssotrace GitHub
# Action (action.yml); it also runs on its own:
#
#   SSOTRACE=bin/ssotrace scripts/action-scan.sh
#
# Environment:
#   SSOTRACE    path to the ssotrace binary (required)
#   SCAN_PATHS  git pathspecs, one per line (default: every tracked .har)
#   GITHUB_OUTPUT  if set, outputs are written there
#
# In a pull request the file names and contents are chosen by whoever
# opened it, so neither is ever evaluated: names are passed as quoted
# arguments, and escaped before they go into GitHub workflow commands.
set -u

: "${SSOTRACE:?set SSOTRACE to the ssotrace binary}"
paths=${SCAN_PATHS:-':(icase)*.har'}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "::error::Not a git repository. Run actions/checkout before this action."
	exit 2
fi

# escape_property makes a value safe inside a workflow command property
# (file=...), per GitHub's escaping rules: % first, then CR, LF, : and ,.
escape_property() {
	printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' -e 's/:/%3A/g' -e 's/,/%2C/g' | awk 'BEGIN{ORS="%0A"} {print}' | sed 's/%0A$//'
}

# escape_data makes a value safe as a workflow command's message.
escape_data() {
	printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | awk 'BEGIN{ORS="%0A"} {print}' | sed 's/%0A$//'
}

# ssotrace's output repeats file names and values from the HAR. While it
# prints, workflow commands are switched off with a token nobody can guess,
# so no line of it can act as a command (::add-mask::, ::error::, ...).
token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
[ -n "$token" ] || exit 2

list=$(mktemp) || exit 2
trap 'rm -f "$list"' EXIT

# Split the pathspecs on newlines only, and without glob expansion, so a
# pattern like *.har reaches git unexpanded.
set -f
old_ifs=$IFS
IFS='
'
# shellcheck disable=SC2086 # word splitting on newlines is intended
git ls-files -- $paths >"$list"
IFS=$old_ifs
set +f

scanned=0
dirty=0
failed=0
while IFS= read -r file; do
	[ -n "$file" ] || continue
	scanned=$((scanned + 1))
	echo "::group::ssotrace scan $(escape_data "$file")"
	echo "::stop-commands::$token"
	"$SSOTRACE" scan "$file" --no-color
	rc=$?
	echo "::$token::"
	echo "::endgroup::"
	prop=$(escape_property "$file")
	case $rc in
	0) ;;
	1)
		dirty=$((dirty + 1))
		echo "::error file=$prop::This HAR file contains secrets (cookies, tokens, passwords, or signatures). Remove it, or replace it with the output of 'ssotrace redact'."
		;;
	*)
		failed=$((failed + 1))
		echo "::error file=$prop::ssotrace could not read this file as a HAR."
		;;
	esac
done <"$list"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		echo "files-scanned=$scanned"
		echo "files-with-secrets=$dirty"
	} >>"$GITHUB_OUTPUT"
fi

echo "Scanned $scanned HAR file(s): $dirty with secrets, $failed unreadable."
[ "$dirty" -eq 0 ] && [ "$failed" -eq 0 ]
