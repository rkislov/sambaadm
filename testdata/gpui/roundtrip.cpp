// Exercise the upstream GPUI INI plugin directly; no copied parser or mock.
// Build with -I<GPUI checkout>/src and upstream src/io/inifile.cpp.
#include <fstream>
#include <iostream>
#include "plugins/ini/iniformat.h"

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    gpui::IniFormat format;
    io::IniFile file;
    std::ifstream input(argv[1], std::ios::binary);
    if (!format.read(input, &file)) {
        std::cerr << format.getErrorString();
        return 1;
    }
    std::ofstream output(argv[2], std::ios::binary);
    if (!format.write(output, &file)) {
        std::cerr << format.getErrorString();
        return 1;
    }
    return output.good() ? 0 : 1;
}
