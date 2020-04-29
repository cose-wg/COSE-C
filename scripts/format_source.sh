#  This script searches all source code files and formats them according to the .clang-format style.

base=clang-format
format=""

# Redirect output to stderr.
exec 1>&2

# check if clang-format is installed
type "$base" >/dev/null 2>&1 && format="$base"
 
path_to_clang_format="$(which $format)"
echo "$path_to_clang_format"

# no versions of clang-format are installed
if [ -z "$format" ]
then
    echo "$base is not installed. Cannot format code..."
    echo "run: pip3 install clang-format"
    exit 1
fi

echo "$format was found, going to format your code..." >&2

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
PROJECT_PATH=$SCRIPTPATH/../
PROJECT_PATH="$( cd "$PROJECT_PATH" >/dev/null 2>&1 ; pwd -P )"

echo "Project path: $PROJECT_PATH"

find "$PROJECT_PATH" \
-not \( -path "*/build/*" -prune \) \
-not \( -path "*/_build/*" -prune \) \
-not \( -path "*/cmake/*" -prune \) \
-not \( -path "*/.vscode/*" -prune \) \
-not \( -path "*/.idea/*" -prune \) \
-not \( -path "*/third_party/*" -prune \) \
-not \( -path "*Coverity_Model.c*" -prune \) \
-not \( -path "*/docs/*" -prune \) \
\( -name "*.h.in" -o -name "*.h" -o -name "*.hpp" -o -name "*.c" -o -name "*.cpp" \) \
| xargs $format -i


echo "done formatting with clang"