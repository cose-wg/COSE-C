#!/bin/sh

#  This script searches all source code files and formats them according to the .cmake-format style.

cmakeFormat="cmake-format"

if [ -z "$cmakeFormat" ]
then
    echo "$cmakeFormat is not installed. Cannot format cmake files..."
    echo "run: pip3 install cmake-format"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
PROJECT_PATH=$SCRIPTPATH/../
PROJECT_PATH="$( cd "$PROJECT_PATH" >/dev/null 2>&1 ; pwd -P )"

echo "$cmakeFormat was found, going to format your cmake scripts..." >&2
echo "formatting from root folder: $PROJECT_PATH" >&2

find "$PROJECT_PATH" \
-not \( -path "*/build/*" -prune \) \
-not \( -path "*/scripts/*" -prune \) \
-not \( -path "*/.vscode/*" -prune \) \
-not \( -path '*/cmake/LCov.cmake' -prune \) \
-not \( -path '*/cmake/Coveralls.cmake' -prune \) \
-not \( -path '*/cmake/CoverallsGenerateGcov.cmake' -prune \) \
-not \( -path '*/cmake/CoverallsClear.cmake' -prune \) \
-not \( -path '*/cmake/FindMbedTLS.cmake' -prune \) \
\( -name *.cmake -o -name CMakeLists.txt ! -iname "*Find*" \) \
| xargs $cmakeFormat -c cmake-format.yaml -i


echo "done formatting with cmake-format"
