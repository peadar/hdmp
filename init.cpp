#include <stdlib.h>
#include <stdio.h>
#include "queue.h"
#include "heap.h"

extern "C" {
    void hdmpInit();
}
class X {
public:
    X() {
        hdmpInit();
    }
} ;
X x;
