#ifdef _WIN32
#include "windows.h"

namespace w32 {
    static DWORD g_oldmode = 0;
    static CONSOLE_SCREEN_BUFFER_INFO g_bufinfo;

    void enable_truecolor() {
        DWORD dwMode;
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(hOut, &g_bufinfo);
        GetConsoleMode(hOut, &dwMode);
        g_oldmode = dwMode;
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }

    void disable_truecolor() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleMode(hOut, g_oldmode);
        SetConsoleTextAttribute(hOut, g_bufinfo.wAttributes);
    }
}

#else

namespace w32 {
    void enable_truecolor() {};
    void disable_truecolor() {};
}

#endif