#!/bin/bash

echo '
begin change dos cr-lf to unix lf
'

find . -name '*.py' -exec dos2unix \{\} \;

echo "CRLF is clean ^_^"
