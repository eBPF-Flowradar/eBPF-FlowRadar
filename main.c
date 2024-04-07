#include <stdio.h>
#include <linux/time.h>
#include <stdbool.h>
#include <unistd.h>

int main() {

    while(true) {

        printf("Hello World!\n");        
        usleep(500000);

    }
    
    return 0;
}