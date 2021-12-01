#include "up_encrypt.h"
#include "string.h"
#include <assert.h>
#include <stdio.h>

static char *readcontent(const char *filename)
{
    FILE *fp;
    int fsize = 0;
    char *fcontent = NULL;

    fp = fopen(filename, "r");
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fcontent = malloc(fsize);
    fread(fcontent, 1, fsize, fp);
    fclose(fp);

    return fcontent;
}

int main()
{
    // test rsa
    char n[] = {210, 46, 10, 188, 123, 25, 216, 56, 233, 84, 203, 198, 246, 22, 2, 150, 134, 177, 79, 47, 182, 132, 140, 128, 188, 216, 200, 207, 249, 164, 145, 176, 218, 126, 161, 96, 161, 201, 52, 82, 184, 196, 90, 106, 91, 206, 198, 43, 202, 13, 207, 24, 28, 7, 185, 114, 122, 19, 218, 213, 27, 113, 159, 245, 92, 36, 174, 12, 122, 227, 247, 134, 134, 121, 73, 110, 201, 80, 162, 134, 146, 36, 146, 175, 198, 30, 155, 51, 80, 248, 5, 1, 170, 12, 206, 172, 1, 225, 89, 94, 9, 248, 92, 171, 14, 87, 144, 46, 230, 152, 194, 216, 60, 79, 175, 102, 50, 148, 223, 229, 127, 75, 16, 21, 135, 121, 191, 46, 14, 60, 120, 252, 197, 42, 250, 158, 181, 63, 205, 38, 166, 157, 186, 140, 24, 155, 3, 154, 229, 42, 171, 131, 71, 81, 171, 53, 179, 223, 217, 245, 108, 199, 83, 109, 179, 225, 38, 31, 148, 41, 32, 133, 239, 186, 97, 243, 73, 95, 242, 156, 138, 159, 88, 172, 169, 204, 187, 154, 177, 87, 165, 239, 132, 126, 2, 80, 165, 16, 124, 32, 105, 98, 73, 209, 54, 201, 250, 217, 2, 202, 169, 43, 220, 105, 214, 136, 25, 175, 240, 128, 127, 118, 116, 169, 76, 221, 107, 252, 214, 116, 34, 247, 235, 39, 248, 202, 156, 9, 25, 240, 111, 252, 60, 118, 173, 225, 202, 117, 241, 114, 117, 195, 184, 171, 124, 111};
    int e = 65537;

    char sig[] = {61, 93, 112, 86, 151, 156, 10, 6, 103, 45, 195, 142, 89, 59, 0, 79, 175, 97, 67, 101, 174, 5, 146, 76, 63, 111, 116, 113, 183, 138, 176, 31, 189, 60, 137, 78, 106, 188, 226, 2, 95, 168, 117, 56, 31, 24, 63, 12, 77, 100, 207, 82, 2, 42, 228, 63, 95, 149, 76, 37, 52, 187, 212, 69, 68, 124, 146, 138, 59, 7, 124, 233, 84, 107, 111, 181, 1, 139, 152, 57, 133, 175, 60, 56, 45, 23, 204, 19, 168, 245, 116, 7, 17, 58, 205, 204, 62, 48, 146, 7, 195, 193, 49, 117, 61, 243, 113, 222, 212, 220, 46, 28, 29, 222, 99, 174, 138, 4, 34, 209, 39, 117, 151, 90, 68, 40, 82, 157, 16, 121, 81, 84, 221, 94, 187, 221, 197, 74, 254, 37, 102, 251, 189, 69, 22, 80, 141, 254, 193, 235, 29, 189, 230, 120, 77, 215, 157, 26, 14, 197, 35, 57, 131, 158, 18, 91, 238, 174, 228, 199, 152, 48, 20, 110, 68, 135, 165, 209, 93, 42, 178, 7, 189, 152, 136, 108, 228, 62, 191, 232, 37, 230, 244, 32, 17, 116, 82, 27, 223, 195, 211, 77, 254, 104, 27, 47, 84, 224, 79, 145, 33, 222, 177, 145, 125, 168, 45, 35, 231, 224, 118, 85, 196, 242, 214, 157, 174, 184, 60, 205, 243, 133, 87, 125, 201, 24, 23, 165, 47, 97, 115, 249, 244, 209, 186, 33, 17, 15, 217, 217, 197, 226, 16, 44, 209, 134};

    char message[] = "hello world";
    PubPKey *pkey;
    int ret = pub_pkey_from_component(e, &n[0], 256, &pkey);
    assert(ret == 0);

    print_pub_pkey(pkey);

    ret = pub_pkey_verify(pkey, &message[0], 11, &sig[0], 256);
    assert(ret == 0);

    // test sha256
    char input[] = "hello world";
    const unsigned char *output;
    unsigned long output_len;
    sha256(&input[0], 11, &output, &output_len);
    char hash[] = {185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233};
    assert(strncmp(output, &hash[0], 32) == 0);

    //test email
    char fpath[] = "./special_ch.eml";
    char *email_s = readcontent(&fpath[0]);
    printf("email:%s\n",email_s);
    Email *email;
    ret = get_email(email_s, strlen(email_s), &email);
    printf("%i\n",ret);
    assert(ret == 0);
    print_email(email);
    char subject[] = "subject";
    const uint8_t *subject_header;

    unsigned long subject_header_len;
    ret = get_header_value(email, &subject[0], 7, &subject_header, &subject_header_len);
    printf("ret:%i\n", ret);
    assert(ret == 0);
    return 0;
}