#include <Windows.h>
DWORD http_get_content(char *target, unsigned char **response_data);
DWORD http_post_binary(char *target, unsigned char *post_data, int post_data_length, unsigned char **response_data);