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
    while (1)
    {
        //test email
        char fpath[] = "./special_ch.eml";
        char *email_s = readcontent(&fpath[0]);

        int ret = 0;
        Email *email;
        ret = get_email(email_s, strlen(email_s), &email);
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

        uint8_t *from_res;
        unsigned long from_res_len;
        ret = get_email_from_header(email, &from_res, &from_res_len);
        if (ret != 0)
        {
            return ret;
        }
        printf("from header:%s\n", from_res);

        const uint8_t **dkim_msg;
        unsigned long dkim_msg_len;
        ret = get_email_dkim_msg(email, &dkim_msg, &dkim_msg_len);
        if (ret != 0)
        {
            printf("ret:%d", ret);
            return ret;
        }
        printf("dkim msg:%s\n", dkim_msg[0]);
        for (int i = 0; i < dkim_msg_len; i++)
        {
            rust_free_box(dkim_msg[i]);
        }
        rust_free_box(dkim_msg);

        const uint8_t **dkim_sig;
        const unsigned long *dkim_sig_len;
        unsigned long dkim_sig_num;
        ret = get_email_dkim_sig(email, &dkim_sig, &dkim_sig_len, &dkim_sig_num);
        if (ret != 0)
        {
            return ret;
        }
        printf("dkim sig:%s\n", *dkim_sig);
        printf("dkim sig len:%d\n", dkim_sig_len[0]);
        printf("dkim sig num:%d\n", dkim_sig_num);
        for (int i = 0; i < dkim_sig_num; i++)
        {
            rust_free_vec(dkim_sig[i], dkim_sig_len[i], dkim_sig_len[i]);
        }

        drop_email(email);
        printf("finish");
    }

    return 0;
}