#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>

void func(int argc, char* argv[], uint32_t t[])
{
    FILE * f;
    for(int i = 0;i<argc-1;i++)
    {
        f = fopen(argv[i+1], "rb");
        if(f == NULL)
        {
            fprintf(stderr, "No File");
            exit(-1);
        }
        size_t size = fread(t+i, 1, sizeof(uint32_t), f);
        if(size != sizeof(uint32_t))
        {
            fprintf(stderr, "fread return: %lu\n", size);
            exit(-1);
        }
        t[i] = ntohl(t[i]);
        fclose(f);
    }
}

int main(int argc, char* argv[])
{
    if(argc > 3)
    {
        fprintf(stderr, "Too many arg");
        exit(-1);
    }
    uint32_t t[2] = {0x0000};
    func(argc, argv, t);
    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)", t[0], t[0], t[1], t[1], t[0]+t[1], t[0]+t[1]);
}