#!/bin/sh
# license-check.sh enforces the dependency license allowlist across the whole
# Go build list and keeps NOTICE in sync with it.
#
# Usage:
#   scripts/license-check.sh             report every dependency (module,
#                                        version, SPDX id) and fail when any
#                                        of its license files has no
#                                        detectable license or one outside
#                                        the allowlist
#   scripts/license-check.sh --notice    regenerate NOTICE from the same scan
#   scripts/license-check.sh --selftest  run the classifier against embedded
#                                        fixtures (offline; no go command)
#
# The scan enumerates `go list -m -json all`, skips the main module and
# resolves the Replace field first, so replaced modules are checked as they
# are actually built. Licenses are located in the Go module cache
# ($GOMODCACHE) with a vendor/ fallback; a dependency whose source cannot be
# found is a failure, never a skip. Run `go mod download all` first (the
# Makefile target does) to populate the cache.
#
# License files are matched by name (LICENSE*, COPYING*, UNLICENSE*) and
# classified by scanning for the canonical core phrases in classify below.
# Every allowlisted permissive family (MIT, BSD-2/3, Apache-2.0, ISC, 0BSD,
# MPL-2.0, PostgreSQL, Unlicense) must match its grant, conditions and
# disclaimer together, so a bare fragment plus unrecognized terms is
# unknown, not that license. A residual-restriction list (for example
# "non-commercial", "evaluation only", "proprietary") fails a file even
# when an allowlisted marker also matched in it. Each file is classified on
# its own and must classify to an allowlisted id: an allowlisted file never
# masks a disallowed or unrecognized one, and an unrecognized license file
# is a failure, not a skip. Documentation-only license files (for example
# LICENSE.docs) are ignored: they cover the module's prose, not the code
# that ships.
#
# Classification is a heuristic, not legal advice: a crafted file that
# embeds the complete canonical text of an allowed license alongside extra
# restrictive terms can still classify as that license. NOTICE review and
# human review of dependency licenses remain part of the process; this
# check only catches marker-level mismatches.
set -eu

# Every id in this list is accepted; a detected id outside it fails the gate.
# The composite ids seen across the current build list (for example
# Apache-2.0/MIT) are accepted when every part is listed here.
ALLOWLIST="Apache-2.0 BSD-3-Clause BSD-2-Clause ISC 0BSD MIT MPL-2.0 PostgreSQL Unlicense"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE=check
case "${1:-}" in
'') ;;
--notice) MODE=notice ;;
--selftest) MODE=selftest ;;
*)
	echo "license-check: unknown argument '$1'" >&2
	echo "license-check: usage: $0 [--notice|--selftest]" >&2
	exit 2
	;;
esac

# classify FILE... prints the slash-joined SPDX ids detected in the files,
# or nothing when no known marker is present. The report order is fixed:
# Apache-2.0, BSD-3-Clause, BSD-2-Clause, ISC, 0BSD, MIT, MPL-2.0,
# PostgreSQL, Unlicense, then the copyleft/source-available ids:
# AGPL-3.0, LGPL-2.1, LGPL-2.0, LGPL-3.0, GPL-2.0, GPL-3.0, AGPL, LGPL,
# GPL, SSPL-1.0, SSPL, BUSL-1.1, BUSL, the CC-BY-NC family and
# Commons-Clause. The failing id "Restricted" is reported when a file
# carries residual restriction language next to an allowlisted marker.
classify() {
	awk '
	function add(id) {
		if (have[id]++) return
		out = (out == "") ? id : out "/" id
	}
	# permissive_only reports whether every detected id belongs to an
	# allowlisted permissive family; a nonfree id (GPL, SSPL, ...) already
	# fails the gate on its own.
	function permissive_only(   n, parts, i) {
		if (out == "") return 0
		n = split(out, parts, "/")
		for (i = 1; i <= n; i++) {
			if (parts[i] != "Apache-2.0" && parts[i] != "BSD-3-Clause" &&
			    parts[i] != "BSD-2-Clause" && parts[i] != "ISC" &&
			    parts[i] != "0BSD" && parts[i] != "MIT" &&
			    parts[i] != "MPL-2.0" && parts[i] != "PostgreSQL" &&
			    parts[i] != "Unlicense")
				return 0
		}
		return 1
	}
	{ text = text " " $0 }
	END {
		gsub(/[[:space:]]+/, " ", text)
		low = tolower(text)

		# Allowlisted permissive families are matched by their canonical
		# core phrases only: a grant fragment alone is not a license. The
		# shared disclaimer shape below covers the "THE SOFTWARE IS
		# PROVIDED "AS IS"" wording of MIT/BSD/ISC/0BSD/Unlicense and
		# the PostgreSQL "SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
		# BASIS" wording.
		as_is = ((low ~ /software is provided/ ||
		          low ~ /software provided hereunder/ ||
		          low ~ /as is. basis/) && low ~ /as is/)

		# Apache-2.0: full text needs the terms header plus a license URL
		# (the https:// spelling and the LICENSE-2.0-less appendix URL are
		# both shipped in the wild); the appendix-only notice is complete
		# only with the versioned LICENSE-2.0 URL and an AS IS basis.
		if (text ~ /Apache License/ && text ~ /Version 2\.0/ &&
		    ((text ~ /TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/ &&
		      text ~ /https?:\/\/www\.apache\.org\/licenses\//) ||
		     (text ~ /You may obtain a copy of the License at/ &&
		      text ~ /https?:\/\/www\.apache\.org\/licenses\/LICENSE-2\.0/ && as_is)))
			add("Apache-2.0")

		# BSD-2/3-Clause: header, both redistribution conditions and the
		# disclaimer; BSD-3 additionally carries the name/endorsement
		# clause.
		if (text ~ /Redistribution and use in source and binary forms/ &&
		    text ~ /Redistributions of source code must retain/ &&
		    text ~ /Redistributions in binary form must reproduce/ && as_is) {
			if (text ~ /Neither the name/ || text ~ /endorse or promote/) add("BSD-3-Clause")
			else add("BSD-2-Clause")
		}

		# ISC and 0BSD share the grant and disclaimer; ISC alone carries
		# the copyright-notice condition.
		if ((text ~ /Permission to use, copy, modify, and\/or distribute this software for any purpose/ ||
		     text ~ /Permission to use, copy, modify, and distribute this software for any purpose/) &&
		    text ~ /with or without fee is hereby granted/ && as_is) {
			if (text ~ /provided that the (above )?copyright notice/) add("ISC")
			else add("0BSD")
		}

		# MIT: the grant, the notice condition and the disclaimer together.
		# MIT No Attribution is the variant whose complete canonical text
		# omits the condition and names itself in the title.
		if (text ~ /Permission is hereby granted, free of charge/ && as_is &&
		    (text ~ /copyright notice and this permission notice/ ||
		     text ~ /MIT No Attribution/))
			add("MIT")

		if (text ~ /Mozilla Public License/ && low ~ /version 2\.0/ &&
		    (text ~ /Covered Software/ || text ~ /Exhibit A/ || text ~ /1\. Definitions/))
			add("MPL-2.0")

		if ((text ~ /Permission to use, copy, modify, and distribute this software and its documentation for any purpose/ ||
		     text ~ /PostgreSQL License[[:space:]]/) &&
		    text ~ /paragraph and the following two paragraphs appear in all copies/ && as_is)
			add("PostgreSQL")

		if (text ~ /free and unencumbered software released into the public domain/ &&
		    text ~ /Anyone is free to copy, modify, publish, use, compile, sell, or distribute/ && as_is)
			add("Unlicense")
		# Copyleft and source-available licenses. Full texts are matched by
		# their canonical header date; the MPL-2.0 secondary-license list,
		# which names GPL, LGPL and AGPL in title case without dates, must not
		# trip these. Short notices are matched by the FSF attribution phrase,
		# which MPL-2.0 does not use either.
		if (text ~ /GNU AFFERO GENERAL PUBLIC LICENSE/ && text ~ /Version 3, 19 November 2007/) add("AGPL-3.0")
		if (text ~ /GNU LESSER GENERAL PUBLIC LICENSE/ && text ~ /Version 2\.1, February 1999/) add("LGPL-2.1")
		if (text ~ /GNU LESSER GENERAL PUBLIC LICENSE/ && text ~ /Version 2, June 1991/) add("LGPL-2.0")
		if (text ~ /GNU LESSER GENERAL PUBLIC LICENSE/ && text ~ /Version 3, 29 June 2007/) add("LGPL-3.0")
		if (text ~ /GNU GENERAL PUBLIC LICENSE/ && text ~ /Version 2, June 1991/) add("GPL-2.0")
		if (text ~ /GNU GENERAL PUBLIC LICENSE/ && text ~ /Version 3, 29 June 2007/) add("GPL-3.0")
		if (low ~ /under the terms of the gnu affero general public license as published by the free software foundation/) {
			if (low ~ /either version 3|version 3 of the license/) add("AGPL-3.0")
			else add("AGPL")
		}
		if (low ~ /under the terms of the gnu lesser general public license as published by the free software foundation/) {
			if (low ~ /either version 2\.1|version 2\.1 of the license/) add("LGPL-2.1")
			else if (low ~ /either version 3|version 3 of the license/) add("LGPL-3.0")
			else add("LGPL")
		}
		if (low ~ /under the terms of the gnu general public license as published by the free software foundation/) {
			if (low ~ /either version 3|version 3 of the license/) add("GPL-3.0")
			else if (low ~ /either version 2|version 2 of the license/) add("GPL-2.0")
			else add("GPL")
		}
		if (low ~ /server side public license/) {
			if (low ~ /version 1|sspl/) add("SSPL-1.0")
			else add("SSPL")
		}
		if (low ~ /business source license/) {
			if (text ~ /1\.1/) add("BUSL-1.1")
			else add("BUSL")
		}
		if (low ~ /attribution-noncommercial/) {
			cc = "CC-BY-NC"
			if (low ~ /attribution-noncommercial-sharealike/) cc = "CC-BY-NC-SA"
			else if (low ~ /attribution-noncommercial-noderivatives/) cc = "CC-BY-NC-ND"
			if (text ~ /4\.0/) cc = cc "-4.0"
			else if (text ~ /3\.0/) cc = cc "-3.0"
			else if (text ~ /2\.5/) cc = cc "-2.5"
			else if (text ~ /2\.0/) cc = cc "-2.0"
			else if (text ~ /1\.0/) cc = cc "-1.0"
			add(cc)
		}
		if (low ~ /commons clause/) add("Commons-Clause")

		# Residual restriction language is a denial independent of the
		# matched id: a file cannot launder "evaluation only" or
		# "proprietary" terms with an allowlisted marker elsewhere in the
		# same file. The non-commercial phrases exclude the Unlicense
		# grant wording ("commercial or non-commercial"), which is
		# permissive. Files whose only ids are permissive families are
		# reported as "Restricted", which is not in the allowlist and
		# therefore fails the gate; files that also matched a nonfree id
		# keep that id, which fails on its own.
		noncomm = ((low ~ /non-commercial/ || low ~ /noncommercial/) &&
		           low !~ /commercial or non-commercial/ &&
		           low !~ /commercial and non-commercial/)
		restricted = (noncomm || low ~ /not for commercial/ ||
		              low ~ /evaluation only/ || low ~ /research only/ ||
		              low ~ /no derivative/ || low ~ /noderivatives/ ||
		              low ~ /proprietary/ || low ~ /internal use only/ ||
		              low ~ /redistribution is prohibited/ ||
		              low ~ /may not be redistributed/)
		if (restricted && permissive_only()) out = "Restricted"
		print out
	}
	' "$@"
}

# list_modules reads `go list -m -json all` output on stdin and prints one
# tab-separated record per module:
#   path version replace-path replace-version replace-dir dir
# The main module is skipped. The parser tracks object depth instead of
# matching go list's indentation, so it stays valid if the formatting shifts.
list_modules() {
	awk '
	function value(line,   v) {
		v = line
		sub(/^"[A-Za-z]+"[[:space:]]*:[[:space:]]*/, "", v)
		if (v ~ /^"/) {
			sub(/^"/, "", v)
			sub(/",?[[:space:]]*$/, "", v)
		}
		return v
	}
	function reset() {
		path = ""; version = ""; dir = ""
		rpath = ""; rversion = ""; rdir = ""
		main = 0; depth = 0
	}
	function field(s) {
		return (s == "") ? "-" : s
	}
	function emit() {
		if (path != "" && !main)
			printf "%s\t%s\t%s\t%s\t%s\t%s\n", field(path), field(version), field(rpath), field(rversion), field(rdir), field(dir)
	}
	BEGIN { reset() }
	{
		line = $0
		sub(/^[[:space:]]+/, "", line)
		if (line == "{") { depth = 1; next }
		if (line == "}" || line == "},") {
			if (depth == 2) { depth = 1; next }
			if (depth == 1) { emit(); reset(); next }
		}
		if (line == "\"Replace\": {") { depth = 2; next }
		if (line ~ /^"/) {
			key = line
			sub(/^"/, "", key)
			sub(/".*$/, "", key)
			v = value(line)
			if (depth == 1) {
				if (key == "Path") path = v
				else if (key == "Version") version = v
				else if (key == "Dir") dir = v
				else if (key == "Main") main = 1
			} else if (depth == 2) {
				if (key == "Path") rpath = v
				else if (key == "Version") rversion = v
				else if (key == "Dir") rdir = v
			}
		}
	}
	'
}

# escape prints the module cache escaping of a module path or version:
# every uppercase letter becomes "!" followed by its lowercase equivalent.
escape() {
	awk -v s="$1" 'BEGIN {
		out = ""
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (c ~ /[A-Z]/) out = out "!" tolower(c)
			else out = out c
		}
		print out
	}'
}

# resolve_dir prints the directory holding a dependency's source, preferring
# the replacement (Replace.Dir, a local replace path, or the replaced
# module@version cache entry), then the module's own cache entry, then
# vendor/. Returns non-zero when none exists.
resolve_dir() {
	_path=$1; _version=$2; _rpath=$3; _rversion=$4; _rdir=$5; _dir=$6
	if [ -n "$_rdir" ] && [ -d "$_rdir" ]; then
		printf '%s\n' "$_rdir"
		return 0
	fi
	if [ -n "$_rpath" ]; then
		case "$_rpath" in
		/*)
			if [ -d "$_rpath" ]; then
				printf '%s\n' "$_rpath"
				return 0
			fi
			;;
		./* | ../*)
			if [ -d "$ROOT/${_rpath#./}" ]; then
				printf '%s\n' "$ROOT/${_rpath#./}"
				return 0
			fi
			;;
		*)
			if [ -n "$_rversion" ]; then
				_d="$CACHE/$(escape "$_rpath")@$(escape "$_rversion")"
				if [ -d "$_d" ]; then
					printf '%s\n' "$_d"
					return 0
				fi
			fi
			;;
		esac
	fi
	if [ -n "$_dir" ] && [ -d "$_dir" ]; then
		printf '%s\n' "$_dir"
		return 0
	fi
	if [ -n "$_path" ] && [ -n "$_version" ]; then
		_d="$CACHE/$(escape "$_path")@$(escape "$_version")"
		if [ -d "$_d" ]; then
			printf '%s\n' "$_d"
			return 0
		fi
	fi
	if [ -n "$_path" ] && [ -d "$ROOT/vendor/$_path" ]; then
		printf '%s\n' "$ROOT/vendor/$_path"
		return 0
	fi
	return 1
}

# allowed_id reports success when every "/"-separated part of the detected id
# is in ALLOWLIST.
allowed_id() {
	_old_ifs=$IFS
	IFS=/
	_allowed=0
	for _part in $1; do
		case " $ALLOWLIST " in
		*" $_part "*) ;;
		*)
			_allowed=1
			break
			;;
		esac
	done
	IFS=$_old_ifs
	[ "$_allowed" -eq 0 ]
}

# license_files SRC prints, one per line in a stable order, the files the
# scan treats as a dependency's license documents: LICENSE*, COPYING* and
# UNLICENSE* at the module root. Documentation companions (LICENSE.docs) and
# Go sources (LICENSE.go) are excluded, so prose and code helpers are never
# classified as licenses.
license_files() {
	find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'UNLICENSE*' \) |
		LC_ALL=C sort |
		while IFS= read -r _lf; do
			case "${_lf##*/}" in
			*.[Gg][Oo]) continue ;;
			*.[Dd][Oo][Cc][Ss]) continue ;;
			esac
			printf '%s\n' "$_lf"
		done
}

# collect_licenses SRC OUT writes one tab-separated record per license file:
#   file<TAB>status<TAB>id
# where status is ok (id allowlisted), bad (recognized but outside the
# allowlist) or unknown (no known marker); id is empty for unknown and is
# last so POSIX read never loses the status field. Prints the number of
# license files examined. Each file is classified on its own, so an
# allowlisted file cannot mask a disallowed or unrecognized one.
collect_licenses() {
	_csrc=$1
	_cout=$2
	_cn=0
	: > "$_cout"
	license_files "$_csrc" > "$TMPDIR_ROOT/licfiles.enum"
	while IFS= read -r _cf; do
		_cn=$((_cn + 1))
		_cid="$(classify "$_cf")"
		if [ -z "$_cid" ]; then
			printf '%s\tunknown\t\n' "$_cf" >> "$_cout"
		elif allowed_id "$_cid"; then
			printf '%s\tok\t%s\n' "$_cf" "$_cid" >> "$_cout"
		else
			printf '%s\tbad\t%s\n' "$_cf" "$_cid" >> "$_cout"
		fi
	done < "$TMPDIR_ROOT/licfiles.enum"
	printf '%s\n' "$_cn"
}

# license_verdict DIR prints the judgement the scan reaches for a module:
# "PASS <ids>" when every license file is allowlisted, "FAIL <ids>" when a
# file is recognized but disallowed, "FAIL UNRECOGNIZED" when a file has no
# known marker, and "FAIL NO-LICENSE-FILE" when nothing was found.
license_verdict() {
	_lv_eval="$TMPDIR_ROOT/verdict.tsv"
	_lv_n="$(collect_licenses "$1" "$_lv_eval")"
	if [ "$_lv_n" -eq 0 ]; then
		printf 'FAIL NO-LICENSE-FILE\n'
		return 0
	fi
	_lv_bad=
	_lv_unknown=0
	while IFS="$(printf '\t')" read -r _lv_f _lv_status _lv_id; do
		case "$_lv_status" in
		unknown) _lv_unknown=1 ;;
		bad) _lv_bad="$_lv_bad${_lv_bad:+/}$_lv_id" ;;
		esac
	done < "$_lv_eval"
	if [ "$_lv_unknown" -ne 0 ]; then
		printf 'FAIL UNRECOGNIZED\n'
	elif [ -n "$_lv_bad" ]; then
		printf 'FAIL %s\n' "$_lv_bad"
	else
		: > "$TMPDIR_ROOT/verdict-text"
		while IFS="$(printf '\t')" read -r _lv_f _lv_status _lv_id; do
			cat "$_lv_f" >> "$TMPDIR_ROOT/verdict-text"
			printf '\n' >> "$TMPDIR_ROOT/verdict-text"
		done < "$_lv_eval"
		printf 'PASS %s\n' "$(classify "$TMPDIR_ROOT/verdict-text")"
	fi
}

run_selftest() {
	_dir="$TMPDIR_ROOT/fixtures"
	mkdir -p "$_dir"
	_failures=0
	check_fixture() {
		_name=$1
		_expected=$2
		_got="$(classify "$_dir/$_name")"
		if [ "$_got" = "$_expected" ]; then
			echo "license-check: selftest ok: $_name -> '$_got'"
		else
			echo "license-check: selftest FAIL: $_name: expected '$_expected', got '$_got'" >&2
			_failures=$((_failures + 1))
		fi
	}
	check_dir_fixture() {
		_name=$1
		_expected=$2
		_got="$(license_verdict "$_dir/$_name")"
		if [ "$_got" = "$_expected" ]; then
			echo "license-check: selftest ok: $_name -> '$_got'"
		else
			echo "license-check: selftest FAIL: $_name: expected '$_expected', got '$_got'" >&2
			_failures=$((_failures + 1))
		fi
	}

	# mit_text prints the canonical MIT text; the classifier requires the
	# grant, the notice condition and the disclaimer together. apache_text
	# prints a canonical Apache-2.0 text (header, terms, disclaimer,
	# appendix). mit_fragment_text is the bare grant sentence that must NOT
	# classify as MIT, and proprietary_text is unrecognized restriction
	# wording. Fixtures compose these so the same-file masking cases use
	# exactly the reviewer's material.
	mit_text() {
		cat <<'EOF'
MIT License

Copyright (c) 2024 Example Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
	}
	mit_fragment_text() {
		cat <<'EOF'
MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
EOF
	}
	proprietary_text() {
		cat <<'EOF'
Proprietary License
Copyright (c) 2024 Example Corp. All rights reserved. Redistribution is
prohibited without prior written permission.
EOF
	}
	apache_text() {
		cat <<'EOF'
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License.

   END OF TERMS AND CONDITIONS

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
EOF
	}

	apache_text > "$_dir/apache"
	mit_fragment_text > "$_dir/mit-partial"
	mit_text > "$_dir/mit-full"
	{ mit_fragment_text; proprietary_text; } > "$_dir/mit-proprietary"
	{
		mit_text
		printf '\nThis software is made available for non-commercial evaluation only.\n'
	} > "$_dir/mit-restricted"
	mit_text > "$_dir/mit"

	cat > "$_dir/bsd2" <<'EOF'
Copyright (c) 2024 Example Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
EOF

	cat > "$_dir/bsd3" <<'EOF'
Copyright (c) 2024 Example Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE.
EOF

	cat > "$_dir/bsd3-variant" <<'EOF'
Copyright (c) 2024 Example Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
The names of its contributors may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE.
EOF

	cat > "$_dir/isc" <<'EOF'
ISC License

Copyright (c) 2024 Example Authors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
EOF

	cat > "$_dir/0bsd" <<'EOF'
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES.
EOF

	cat > "$_dir/mpl" <<'EOF'
Copyright (c) 2014 Example, Inc.
Mozilla Public License, version 2.0
1. Definitions
1.1. "Contributor" means each individual or legal entity that creates,
contributes to the creation of, or owns Covered Software.
EOF

	cat > "$_dir/postgresql" <<'EOF'
PostgreSQL License

Copyright (c) 2024, Example Authors

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose, without fee, and without a written agreement
is hereby granted, provided that the above copyright notice and this
paragraph and the following two paragraphs appear in all copies.

IN NO EVENT SHALL THE AUTHORS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION.

THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE AUTHORS HAVE
NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
MODIFICATIONS.
EOF

	cat > "$_dir/unlicense" <<'EOF'
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute
this software, either in source code form or as a compiled binary, for any
purpose, commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of
this software dedicate any and all copyright interest in the software to
the public domain. We make this dedication for the benefit of the public
at large and to the detriment of our heirs and successors. We intend this
dedication to be an overt act of relinquishment in perpetuity of all
present and future rights to this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
EOF

	{ apache_text; printf '\n'; mit_text; } > "$_dir/apache-mit"

	cat > "$_dir/unknown" <<'EOF'
Proprietary License
Copyright (c) 2024 Example Corp. All rights reserved. Redistribution is
prohibited without prior written permission.
EOF

	cat > "$_dir/gpl2" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
EOF

	cat > "$_dir/gpl3" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
EOF

	cat > "$_dir/lgpl21" <<'EOF'
                  GNU LESSER GENERAL PUBLIC LICENSE
                       Version 2.1, February 1999
EOF

	cat > "$_dir/lgpl3" <<'EOF'
                   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007
EOF

	cat > "$_dir/agpl3" <<'EOF'
                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007
EOF

	cat > "$_dir/mpl-secondary" <<'EOF'
Mozilla Public License Version 2.0
1. Definitions
1.1. "Contributor" means each individual or legal entity that creates,
contributes to the creation of, or owns Covered Software.
"Secondary License" means either the GNU General Public License, Version 2.0,
the GNU Lesser General Public License, Version 2.1, the GNU Affero General
Public License, Version 3.0, or any later versions of those licenses.
EOF

	cat > "$_dir/sspl" <<'EOF'
Server Side Public License
Version 1

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
1. Definitions
EOF

	cat > "$_dir/busl" <<'EOF'
Business Source License 1.1
License text copyright (c) 2017 MariaDB Corporation Ab, All Rights Reserved.
"Business Source License" is a trademark of MariaDB Corporation Ab.
EOF

	cat > "$_dir/cc-by-nc" <<'EOF'
Creative Commons Attribution-NonCommercial 4.0 International Public License
By exercising the Licensed Rights, You accept and agree to be bound by the
terms and conditions of this Creative Commons Attribution-NonCommercial 4.0
International Public License.
EOF

	cat > "$_dir/commons-clause" <<'EOF'
"Commons Clause" License Condition v1.0
The Software is provided to you by the Licensor under the License, as defined
below, subject to the following condition.
EOF

	mkdir -p "$_dir/dual-nonfree"
	mit_text > "$_dir/dual-nonfree/LICENSE"
	cat > "$_dir/dual-nonfree/COPYING" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
EOF

	mkdir -p "$_dir/masked-unknown"
	mit_text > "$_dir/masked-unknown/LICENSE"
	proprietary_text > "$_dir/masked-unknown/LICENSE-PROPRIETARY"

	mkdir -p "$_dir/dual-free"
	apache_text > "$_dir/dual-free/LICENSE"
	mit_text > "$_dir/dual-free/LICENSE-MIT"

	mkdir -p "$_dir/copyleft-only"
	cat > "$_dir/copyleft-only/COPYING" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
EOF

	mkdir -p "$_dir/stray-readme"
	mit_text > "$_dir/stray-readme/LICENSE"
	cat > "$_dir/stray-readme/README.md" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
EOF
	cat > "$_dir/stray-readme/LICENSE.docs" <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
EOF

	mkdir -p "$_dir/partial-mit"
	mit_fragment_text > "$_dir/partial-mit/LICENSE"

	mkdir -p "$_dir/full-mit"
	mit_text > "$_dir/full-mit/LICENSE"

	mkdir -p "$_dir/same-file-masking"
	{ mit_fragment_text; proprietary_text; } > "$_dir/same-file-masking/LICENSE"

	mkdir -p "$_dir/restricted-mit"
	{
		mit_text
		printf '\nThis software is made available for non-commercial evaluation only.\n'
	} > "$_dir/restricted-mit/LICENSE"

	check_fixture apache "Apache-2.0"
	check_fixture mit "MIT"
	check_fixture mit-full "MIT"
	check_fixture mit-partial ""
	check_fixture mit-proprietary ""
	check_fixture mit-restricted "Restricted"
	check_fixture bsd2 "BSD-2-Clause"
	check_fixture bsd3 "BSD-3-Clause"
	check_fixture bsd3-variant "BSD-3-Clause"
	check_fixture isc "ISC"
	check_fixture 0bsd "0BSD"
	check_fixture mpl "MPL-2.0"
	check_fixture postgresql "PostgreSQL"
	check_fixture unlicense "Unlicense"
	check_fixture apache-mit "Apache-2.0/MIT"
	check_fixture unknown ""
	check_fixture gpl2 "GPL-2.0"
	check_fixture gpl3 "GPL-3.0"
	check_fixture lgpl21 "LGPL-2.1"
	check_fixture lgpl3 "LGPL-3.0"
	check_fixture agpl3 "AGPL-3.0"
	check_fixture mpl-secondary "MPL-2.0"
	check_fixture sspl "SSPL-1.0"
	check_fixture busl "BUSL-1.1"
	check_fixture cc-by-nc "CC-BY-NC-4.0"
	check_fixture commons-clause "Commons-Clause"

	check_dir_fixture dual-nonfree "FAIL GPL-3.0"
	check_dir_fixture masked-unknown "FAIL UNRECOGNIZED"
	check_dir_fixture dual-free "PASS Apache-2.0/MIT"
	check_dir_fixture copyleft-only "FAIL GPL-3.0"
	check_dir_fixture stray-readme "PASS MIT"
	check_dir_fixture partial-mit "FAIL UNRECOGNIZED"
	check_dir_fixture full-mit "PASS MIT"
	check_dir_fixture same-file-masking "FAIL UNRECOGNIZED"
	check_dir_fixture restricted-mit "FAIL Restricted"

	if [ "$_failures" -ne 0 ]; then
		echo "license-check: selftest FAILED ($_failures fixture(s))" >&2
		exit 1
	fi
	echo "license-check: selftest passed ($(find "$_dir" -type f | wc -l | tr -d ' ') fixtures)"
}

TMPDIR_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_ROOT"; rm -f "$ROOT/NOTICE.tmp"' EXIT HUP INT TERM

if [ "$MODE" = selftest ]; then
	run_selftest
	exit 0
fi

CACHE="$(go env GOMODCACHE)"
if [ -z "$CACHE" ]; then
	echo "license-check: go env GOMODCACHE is empty; the module cache cannot be located" >&2
	exit 1
fi

if ! go list -m -json all > "$TMPDIR_ROOT/modules.json"; then
	echo "license-check: go list -m -json all failed; the module graph is not loadable" >&2
	exit 1
fi

list_modules < "$TMPDIR_ROOT/modules.json" | LC_ALL=C sort > "$TMPDIR_ROOT/modules.tsv"
if [ ! -s "$TMPDIR_ROOT/modules.tsv" ]; then
	echo "license-check: go list -m -json all reported no dependencies" >&2
	exit 1
fi

: > "$TMPDIR_ROOT/report.tsv"
violations=0
count=0
while IFS="$(printf '\t')" read -r path version rpath rversion rdir dir; do
	count=$((count + 1))
	if [ "$rpath" = "-" ]; then rpath=; fi
	if [ "$rversion" = "-" ]; then rversion=; fi
	if [ "$rdir" = "-" ]; then rdir=; fi
	if [ "$dir" = "-" ]; then dir=; fi
	if ! src="$(resolve_dir "$path" "$version" "$rpath" "$rversion" "$rdir" "$dir")"; then
		echo "license-check: MISSING SOURCE: $path $version" >&2
		echo "license-check:   no cache entry at $CACHE/$(escape "$path")@$(escape "$version") and no vendor/$path" >&2
		echo "license-check:   run 'go mod download all' and retry" >&2
		violations=$((violations + 1))
		continue
	fi

	# Every license file must stand on its own: a file that matches no marker
	# or a marker outside the allowlist fails the module even when another
	# file is allowlisted, so one license cannot mask another.
	_lic_eval="$TMPDIR_ROOT/lic-eval.tsv"
	found="$(collect_licenses "$src" "$_lic_eval")"
	if [ "$found" -eq 0 ]; then
		echo "license-check: NO LICENSE FILE: $path $version (scanned $src)" >&2
		violations=$((violations + 1))
		continue
	fi
	_bad=0
	while IFS="$(printf '\t')" read -r _lf _lstatus _lid; do
		case "$_lstatus" in
		unknown)
			echo "license-check: NO DETECTABLE LICENSE: $path $version (no marker matched in ${_lf##*/})" >&2
			_bad=1
			;;
		bad)
			echo "license-check: DISALLOWED LICENSE: $path $version is '$_lid', outside the allowlist ($ALLOWLIST)" >&2
			echo "license-check:   offending file: ${_lf##*/}" >&2
			_bad=1
			;;
		esac
	done < "$_lic_eval"
	if [ "$_bad" -ne 0 ]; then
		violations=$((violations + 1))
		continue
	fi
	# Everything passed; the report id is the classifier's view of the
	# combined text, so NOTICE entries keep their existing format.
	: > "$TMPDIR_ROOT/lictext"
	while IFS="$(printf '\t')" read -r _lf _lstatus _lid; do
		cat "$_lf" >> "$TMPDIR_ROOT/lictext"
		printf '\n' >> "$TMPDIR_ROOT/lictext"
	done < "$_lic_eval"
	id="$(classify "$TMPDIR_ROOT/lictext")"
	if [ -z "$id" ]; then
		echo "license-check: NO DETECTABLE LICENSE: $path $version (no marker matched in $src)" >&2
		violations=$((violations + 1))
		continue
	fi
	if ! allowed_id "$id"; then
		echo "license-check: DISALLOWED LICENSE: $path $version is '$id', outside the allowlist ($ALLOWLIST)" >&2
		violations=$((violations + 1))
		continue
	fi
	replacement=
	if [ -n "$rpath" ]; then
		if [ -n "$rversion" ]; then
			replacement="$rpath $rversion"
		else
			replacement="$rpath"
		fi
	fi
	printf '%s\t%s\t%s\t%s\n' "$path" "$version" "$id" "$replacement" >> "$TMPDIR_ROOT/report.tsv"
done < "$TMPDIR_ROOT/modules.tsv"

if [ "$MODE" = notice ]; then
	if [ "$violations" -ne 0 ]; then
		echo "license-check: NOTICE not written: $violations violation(s) must be fixed first" >&2
		exit 1
	fi
	{
		cat <<'EOF'
NOTICE
======

Kiwi CI (github.com/Bel-Consulting-OU/kiwi-ci)

This product includes software developed by the third-party Go modules
listed below. Each block names the module, the version in the build list,
and the SPDX identifier(s) of the license detected for it.

Generated by `make license-notice` (scripts/license-check.sh --notice).
Regenerate and commit after any dependency change.
EOF
		while IFS="$(printf '\t')" read -r path version id replacement; do
			printf '\n%s\n' "----------------------------------------------------------------------"
			printf '%s\n' "$path"
			printf '  version: %s\n' "$version"
			printf '  license: %s\n' "$id"
			if [ -n "$replacement" ]; then
				printf '  replacement: %s\n' "$replacement"
			fi
		done < "$TMPDIR_ROOT/report.tsv"
	} > "$ROOT/NOTICE.tmp"
	mv "$ROOT/NOTICE.tmp" "$ROOT/NOTICE"
	echo "license-check: NOTICE written ($count dependencies, 0 violations)"
	exit 0
fi

echo "license-check: scanned $count dependencies, $violations violation(s)"
if [ "$violations" -ne 0 ]; then
	echo "license-check: FAIL" >&2
	exit 1
fi

awk -F"$(printf '\t')" '{ n[$3]++ } END { for (k in n) printf "%s\t%d\n", k, n[k] }' "$TMPDIR_ROOT/report.tsv" |
	LC_ALL=C sort |
	while IFS="$(printf '\t')" read -r id n; do
		echo "license-check: $id $n"
	done

printf '# module\tversion\tlicense\n'
awk -F"$(printf '\t')" '{ print $1 "\t" $2 "\t" $3 }' "$TMPDIR_ROOT/report.tsv"
echo "license-check: PASS"
