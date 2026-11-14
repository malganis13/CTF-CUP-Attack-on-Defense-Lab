/* Demo fixture: deliberately vulnerable. Never compiled or run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *render(const char *name) {
    char buffer[64];
    char *out = malloc(128);

    strcpy(buffer, name);
    sprintf(out, "<b>%s</b>", buffer);
    system(name);

    return out;
}

static void copy_blob(char *dst, const char *src, size_t len) {
    memcpy(dst, src, len);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    char *html = render(argv[1]);
    printf("%s\n", html);
    copy_blob(html, argv[1], strlen(argv[1]));
    return 0;
}
