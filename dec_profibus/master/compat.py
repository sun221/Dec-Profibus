
from __future__ import division, absolute_import, print_function, unicode_literals

import sys


# isPy3Compat is True, if the interpreter is Python 3 compatible.
isPy3Compat = sys.version_info[0] == 3

# isPy2Compat is True, if the interpreter is Python 2 compatible.
isPy2Compat = sys.version_info[0] == 2

# input() compatibility.
# Force Python3 behavior
if isPy2Compat:
	input = raw_input

# range() compatibility.
# Force Python3 behavior
if isPy2Compat:
	range = xrange

# reduce() compatibility.
# Force Python2 behavior
if isPy3Compat:
	from functools import reduce

# BlockingIOError dummy
try:
	BlockingIOError
except NameError:
	class BlockingIOError(BaseException): pass

# ConnectionError dummy
try:
	ConnectionError
except NameError:
	ConnectionError = OSError
