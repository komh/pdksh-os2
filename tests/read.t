#
# To test:
#   POSIX:
#	- if no -r, \ is escape character
#	    - \newline disappear
#	    - \<IFS> -> don't break here
#	    - \<anything-else> -> <anything-else>
#	- if -r, backslash is not special
#	- if stdin is tty and shell interactive
#	    - prompt for continuation if \newline (prompt to stderr)
#	    - a here-document isn't terminated after newline ????
#	- remaining vars set to empty string (not null)
#	- check field splitting
#	- left over fields and their seperators assigned to last var
#	- exit status is normally 0
#	- exit status is > 0 on eof
#	- exit status > 0 on error
#	- signals interrupt reads
#   extra:
#	- can't change read-only variables
#	- error if var name bogus
#	- set -o allexport effects read
# ksh:
#	x check default variable: REPLY
#	- check -p, -s, -u options
#	- check var?prompt stuff
#	- "echo a b | read x y" sets x,y in parent shell (at&t)
#
name: read-IFS-1
description:
	Simple test, default IFS
stdin:
	echo "A B " > IN
	unset x y z
	read x y z < IN
	echo 1: "x[$x] y[$y] z[$z]"
	echo 1a: ${z-z not set}
	read x < IN
	echo 2: "x[$x]"
expected-stdout:
	1: x[A] y[B] z[]
	1a:
	2: x[A B]
---

name: read-ksh-1
description:
	If no var specified, REPLY is used
stdin:
	echo "abc" > IN
	read < IN
	echo "[$REPLY]";
expected-stdout:
	[abc]
---

name: read-multiline-1
description:
	Check that read works on text files (where text/binary are different).
stdin:
	(echo 123; echo 456; echo 789) > IN
	if test -z "" ; then
	  read data
	  read data1
	  read data2
	  echo "'$data'"
	  echo "'$data1'"
	  echo "'$data2'"
	fi < IN
expected-stdout: 
	'123'
	'456'
	'789'
---

name: read-multiline-2
description:
	Check that read works on pipes.
stdin:
	(echo 123; echo 456; echo 789) | if test -z "" ; then
	  read data
	  read data1
	  read data2
	  echo "'$data'"
	  echo "'$data1'"
	  echo "'$data2'"
	fi
expected-stdout: 
	'123'
	'456'
	'789'
---

