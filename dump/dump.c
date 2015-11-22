#include <stdio.h>
#include <cn-cbor/cn-cbor.h>

void dump_file(char * fileName)
{
    FILE * fp;


    fp = fopen(fileName, "rb");
    
}

int main(int argc, char ** argv)
{
    for (i=1; i<argc; i++) {
        if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
            fprintf(stderr, "No options defined for %s\n", argv[0]);
            exit(-1);
        }
        else {
            dump_file(argv[i]);
        }
    }
    
    exit(0);
}
