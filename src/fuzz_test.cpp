#include <unistd.h>

#define main zig_main
#include "main.cpp"
#undef main

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    char tmp_file_name[] = "/tmp/fuzzXXXXXX";
    int fd = mkstemp(tmp_file_name);
    if (fd < 0) {
        perror("Cannot create temporary file");
        return 0;
    }
    const int num_written = write(fd, data, size);
    close(fd);
    if (num_written != size) {
        fprintf(stderr, "Cannot write to file\n");
        return 0;
    }

    char arg0[] = "zig";
    char arg1[] = "build-exe";
    char* argv[] = { arg0, arg1, tmp_file_name };
    int argc = sizeof(argv) / sizeof(argv[0]);
    zig_main(argc, argv);

    remove(tmp_file_name);
    return 0;
}
