#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/sepol.h>

/* Read-only binary policy inspection. No load_policy or live modification code. */
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: policytool dump|check|roundtrip|contexts POLICY [OUTPUT_OR_CONTEXT_LIST]\n"); return 2; }
    FILE *in=fopen(argv[2],"rb"); if(!in){perror(argv[2]);return 2;}
    if(!strcmp(argv[1],"contexts")) {
        if(argc!=4 || sepol_set_policydb_from_file(in)<0){fclose(in);return 3;}
        fclose(in); FILE *list=fopen(argv[3],"r"); if(!list)return 2;
        char *line=NULL;size_t n=0;int bad=0,count=0;
        while(getline(&line,&n,list)>0){line[strcspn(line,"\r\n")]=0;if(!*line)continue;count++;if(sepol_check_context(line)<0){fprintf(stderr,"INVALID_CONTEXT %s\n",line);bad++;}}
        free(line);fclose(list);printf("contexts=%d invalid=%d\n",count,bad);return bad?4:0;
    }
    sepol_policydb_t *p=NULL;sepol_policy_file_t *pf=NULL;
    if(sepol_policydb_create(&p)<0 || sepol_policy_file_create(&pf)<0)return 3;
    sepol_policy_file_set_fp(pf,in);
    if(sepol_policydb_read(p,pf)<0){fclose(in);return 3;}
    fclose(in);int status=0;
    if(!strcmp(argv[1],"dump")) {
        if(argc!=4)return 2;
        FILE *out=fopen(argv[3],"w");if(!out)return 2;
        status=sepol_kernel_policydb_to_cil(out,&p->p);if(fclose(out))status=-1;
    } else if(!strcmp(argv[1],"roundtrip")) {
        if(argc!=4)return 2;
        FILE *out=fopen(argv[3],"wb");if(!out)return 2;
        sepol_policy_file_set_fp(pf,out);
        status=sepol_policydb_write(p,pf);
        if(fclose(out))status=-1;
        if(status>=0){
            sepol_policydb_t *again=NULL;
            if(sepol_policydb_create(&again)<0)return 3;
            FILE *back=fopen(argv[3],"rb");if(!back)return 2;
            sepol_policy_file_set_fp(pf,back);
            status=sepol_policydb_read(again,pf);fclose(back);
            if(status>=0 && again->p.policyvers!=p->p.policyvers)status=-1;
            sepol_policydb_free(again);
        }
        if(status>=0)printf("roundtrip_ok policy_version=%u\n",p->p.policyvers);
    } else if(strcmp(argv[1],"check"))return 2;
    else printf("readback_ok policy_version=%u\n",p->p.policyvers);
    sepol_policy_file_free(pf);sepol_policydb_free(p);return status<0?4:0;
}
