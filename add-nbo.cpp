#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    if(argc > 3)
    {
        fprintf(stderr, "Too many arg");
        exit(-1);
    }
    FILE * f1;
    uint32_t t[2] = {0x0000};
    for(int i = 0;i<argc-1;i++)
    {
        f1 = fopen(argv[i+1], "rb");
        if(f1 == NULL)
        {
            fprintf(stderr, "No File");
            exit(-1);
        }
        size_t size = fread(t+i, 1, sizeof(uint32_t), f1);
        if(size != sizeof(uint32_t))
        {
            fprintf(stderr, "fread return: %lu\n", size);
            exit(-1);
        }
        t[i] = ntohl(t[i]);
    }
    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)", t[0], t[0], t[1], t[1], t[0]+t[1], t[0]+t[1]);
}