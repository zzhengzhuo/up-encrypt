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
    fcontent = (char *)malloc(fsize);
    fread(fcontent, 1, fsize, fp);
    fclose(fp);

    return fcontent;
}

int main()
{
    int i = 0;
    // do
    // {
    //test email
    char fpath[] = "./special_ch.eml";
    char *email_s = readcontent(&fpath[0]);

    int ret = 0;
    Email *email;
    ret = get_email((const uint8_t *)email_s, strlen(email_s) + 1, &email);
    if (ret != 0)
    {
        return ret;
    }
    printf("%s", email_s);

    // test get subject
    uint8_t *subject_res;
    unsigned long subject_res_len;
    ret = get_email_subject_header(email, &subject_res, &subject_res_len);
    if (ret != 0)
    {
        return ret;
    }
    printf("subject header: %s\n", subject_res);
    rust_free_vec_u8(subject_res, subject_res_len, subject_res_len);

    uint8_t *from_res;
    unsigned long from_res_len;
    ret = get_email_from_header(email, &from_res, &from_res_len);
    if (ret != 0)
    {
        return ret;
    }
    printf("from header:%s\n", from_res);
    rust_free_vec_u8(from_res, from_res_len, from_res_len);

    const uint8_t *const *dkim_msg;
    const unsigned long *dkim_msg_len;
    unsigned long dkim_msg_num;
    ret = get_email_dkim_msg(email, &dkim_msg, &dkim_msg_len, &dkim_msg_num);
    if (ret != 0)
    {
        printf("ret:%d", ret);
        return ret;
    }
    printf("dkim msg:%s\n", dkim_msg[0]);
    printf("dkim msg len:%d\n", dkim_msg_len[0]);
    printf("dkim msg num:%d\n", dkim_msg_num);
    for (int i = 0; i < dkim_msg_num; i++)
    {
        rust_free_vec_u8((uint8_t *)(dkim_msg[i]), dkim_msg_len[i], dkim_msg_len[i]);
    }
    rust_free_vec_usize((uintptr_t *)dkim_msg_len, dkim_msg_num, dkim_msg_num);
    rust_free_ptr_vec((uint8_t **)dkim_msg, dkim_msg_num, dkim_msg_num);

    const uint8_t *const *dkim_sig;
    const unsigned long *dkim_sig_len;
    const uint8_t *const *dkim_selector;
    const unsigned long *dkim_selector_len;
    const uint8_t *const *dkim_sdid;
    const unsigned long *dkim_sdid_len;
    unsigned long dkim_sig_num;
    ret = get_email_dkim_sig(email, &dkim_sig, &dkim_sig_len, &dkim_selector, &dkim_selector_len, &dkim_sdid, &dkim_sdid_len, &dkim_sig_num);
    if (ret != 0)
    {
        return ret;
    }
    printf("dkim sig:%s\n", *dkim_sig);
    printf("dkim sig len:%d\n", dkim_sig_len[0]);
    printf("dkim sig num:%d\n", dkim_sig_num);
    for (int i = 0; i < dkim_sig_num; i++)
    {
        rust_free_vec_u8((uint8_t *)(dkim_sig[i]), dkim_sig_len[i], dkim_sig_len[i]);
    }
    rust_free_vec_usize((uintptr_t *)dkim_sig_len, dkim_sig_num, dkim_sig_num);
    rust_free_ptr_vec((uint8_t **)dkim_sig, dkim_sig_num, dkim_sig_num);

    drop_email(email);
    free(email_s);
    printf("finish[%d]\n", i);
    i++;
    // } while (1);

    return 0;
}