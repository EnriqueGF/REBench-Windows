#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <delayimp.h>
#include <stdio.h>

int main(void) {
    HWND first = GetForegroundWindow();
    BOOL unloaded = __FUnloadDelayLoadedDLL2("USER32.dll");
    HWND second = GetForegroundWindow();
    printf("first=%p unloaded=%u second=%p\n", (void *)first,
           (unsigned)unloaded, (void *)second);
    return unloaded ? 0 : 1;
}
