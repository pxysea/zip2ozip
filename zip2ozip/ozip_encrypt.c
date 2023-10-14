/*
 OPPOENCRYPT by affggh
 D:\Qt\Qt5.12.9\Tools\mingw730_64\bin\mingw32-make
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

#include "tiny-AES-c/aes.h"

#define MAX_DATA_LEN 1024
#define SHA1_LENTH 20
#define ECB 1

/*
 OZIP 文件格式
 Magic OPPOENCRYPT! 0x00 0x00 0x00 0x00
 16byte file size
 40byte Sha1 checksum
 1008byte 0x00
 DATA [每隔4000（hex）加密一次 aes-128-ecb]
*/

/* 
 There are many keys... I choose R9s
         "D6EECF0AE5ACD4E0E9FE522DE7CE381E",  # mnkey
        "D6ECCF0AE5ACD4E0E92E522DE7C1381E",  # mkey
        "D6DCCF0AD5ACD4E0292E522DB7C1381E",  # realkey, R9s CPH1607 MSM8953, Plus, R11, RMX1921 Realme XT, RMX1851EX Realme Android 10, RMX1992EX_11_OTA_1050
        "D7DCCE1AD4AFDCE2393E5161CBDC4321",  # testkey
        "D7DBCE2AD4ADDCE1393E5521CBDC4321",  # utilkey
        "D7DBCE1AD4AFDCE1393E5121CBDC4321",  # R11s CPH1719 MSM8976, Plus
        "D4D2CD61D4AFDCE13B5E01221BD14D20",  # FindX CPH1871 SDM845
        "261CC7131D7C1481294E532DB752381E",  # FindX
        "1Fxu7L83m1qDUM84fvsrQN3iwEjaxeRLEy",  # Realme 2 pro SDM660/MSM8976
        "D4D2CE11D4AFDCE13B3E0121CBD14D20",  # K1 SDM660/MSM8976
        "1C4C1EA3A12531AE491B21BB31613C11",  # Realme 3 Pro SDM710, X, 5 Pro, Q, RMX1921 Realme XT
        "1C4C1EA3A12531AE4A1B21BB31C13C21",  # Reno 10x zoom PCCM00 SDM855, CPH1921EX Reno 5G
        "1C4A11A3A12513AE441B23BB31513121",  # Reno 2 PCKM00 SDM730G
        "1C4A11A3A12589AE441A23BB31517733",  # Realme X2 SDM730G
        "1C4A11A3A22513AE541B53BB31513121",  # Realme 5 SDM665
        "2442CE821A4F352E33AE81B22BC1462E",  # R17 Pro SDM710
        "14C2CD6214CFDC2733AE81B22BC1462C",  # CPH1803 OppoA3s SDM450/MSM8953
        "1E38C1B72D522E29E0D4ACD50ACFDCD6",
        "12341EAAC4C123CE193556A1BBCC232D",
        "2143DCCB21513E39E1DCAFD41ACEDBD7",
        "2D23CCBBA1563519CE23C1C4AA1E3412",  # A77 CPH1715 MT6750T
        "172B3E14E46F3CE13E2B5121CBDC4321",  # Realme 1 MTK P60 R15
        "ACAA1E12A71431CE4A1B21BBA1C1C6A2",  # Realme U1 RMX1831 MTK P70
        "ACAC1E13A72531AE4A1B22BB31C1CC22",  # Realme 3 RMX1825EX P70
        "1C4411A3A12533AE441B21BB31613C11",  # A1k CPH1923 MTK P22
        "1C4416A8A42717AE441523B336513121",  # Reno 3 PCRM00 MTK 1000L, CPH2059 OPPO A92, CPH2067 OPPO A72
        "55EEAA33112133AE441B23BB31513121",  # RenoAce SDM855Plus
        "ACAC1E13A12531AE4A1B21BB31C13C21",  # Reno, K3
        "ACAC1E13A72431AE4A1B22BBA1C1C6A2",  # A9
        "12CAC11211AAC3AEA2658690122C1E81",  # A1,A83t
        "1CA21E12271435AE331B81BBA7C14612",  # CPH1909 OppoA5s MT6765
        "D1DACF24351CE428A9CE32ED87323216",  # Realme1(reserved)
        "A1CC75115CAECB890E4A563CA1AC67C8",  # A73(reserved)
        "2132321EA2CA86621A11241ABA512722",  # Realme3(reserved)
        "22A21E821743E5EE33AE81B227B1462E"
        #F3 Plus CPH1613 - MSM8976
*/

void Usage();
unsigned long long getfilesize(FILE *fp);
const char *readline(FILE *file) ;

int writeheaderconfig(const char * filename,FILE *fp2);
//uint8_t key[16] = {0xd6, 0xdc, 0xcf, 0x0a, 0xd5, 0xac, 0xd4, 0xe0, 0x29, 0x2e, 0x52, 0x2d, 0xb7, 0xc1, 0x38, 0x1e};
//OPPO R15
uint8_t key[16] = {0x17,0x2B,0x3E,0x14,0xE4,0x6F,0x3C,0xE1,0x3E,0x2B,0x51,0x21,0xCB,0xDC,0x43,0x21};
struct AES_ctx ctx;

int main(int argc, char *argv[]) {
	if(argc<2){
		Usage();
		return 0;
	}
	FILE *fp,*fpout;
	char newfile[256],sha1[40];
	int i;
    unsigned long long size;
	strcpy(newfile, argv[1]);
	strcat(newfile, ".ozip");
	fp = fopen(argv[1],"rb");
	if(access(argv[1],0)!=0){
		fprintf(stderr, "File %s not exist... \n", argv[1]);
		return 1;
	}
	// Header
	fpout = fopen(newfile, "wb"); // open new file
	fprintf(stdout, "Gerenating file %s...\n", newfile);
	fputs("OPPOENCRYPT!", fpout); // generate header
	// Size
	fprintf(stdout, "Get %s size...", argv[1]);

	for(i=0;i<4;i++){
		fputc(0x00, fpout); // 补0
	}
	
	size = getfilesize(fp);

	fseek(fp, 0, SEEK_SET);
	//fclose(fp);
    
	fprintf(stdout, "%lld...\n", size);
	fprintf(fpout, "%lld", size);
	while(ftell(fpout)!=32){
		fputc(0x00, fpout); // 补0
	}

    //2. Write data Chk sum
	// SHA1
    SHA_CTX sha1_ctx;
    //FILE *fp = NULL;
    char *strFilePath = argv[1];
    unsigned char SHA1result[SHA1_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    i = 0;
    memset(SHA1result,0x0,SHA1_LENTH);
    do
    {
        SHA1_Init(&sha1_ctx);
        while(!feof(fp))
        {
            memset(DataBuff, 0x00, sizeof(DataBuff));

            len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
            if(len)
            {
                t += len;
                //printf("len = [%d] 1\n", len);
                SHA1_Update(&sha1_ctx, DataBuff, len);   //将当前文件块加入并更新SHA1
            }
        }

        //printf("len = [%d]\n", t);

        SHA1_Final(SHA1result,&sha1_ctx);       //获取SHA1

        fprintf(stdout, "Get file sha1 : ");
        for(i = 0; i<SHA1_LENTH; i++)   //将SHA1以16进制输出
        {
            fprintf(stdout, "%02x", (int)SHA1result[i]);
			fprintf(fpout, "%02x", (int)SHA1result[i]);
            
        }
        fprintf(stdout, "\n");

    } while(0);

	while(ftell(fpout)<0x50){
		fputc(0x00, fpout); // 补0
	}

	// 3. Write Header Config
    if(argc>2){
        //fprintf(stdout, "Read config file: %s...\n", argv[2]);
        if(access(argv[2],0)!=0){
            fprintf(stderr, "Config file %s not exist... \n", argv[2]);
            return 1;
	    }
        if(writeheaderconfig(argv[2],fpout) !=0){
            fprintf(stderr, "Write header error %s not exist... \n", argv[2]);
            return -2;
        };
        fprintf(stdout, "Write Header config success.\n");
    }

	while(ftell(fpout)!=4176){
		fputc(0x00, fpout); // 补0
	}
    // if(1)
    // {
    //     fclose(fpout);
    //     fclose(fp);
    //     return 0;
    // }
	// 4. Data encryption
	fprintf(stdout, "Encrypt File...\n");
	uint8_t buf[16], buf2[16384];
	AES_init_ctx(&ctx, key);
	fseek(fp, 0 , SEEK_SET);
	while(feof(fp)==0){
		fread(buf, 16, 1, fp);
		AES_ECB_encrypt(&ctx, buf);
		fwrite(buf, 16, 1, fpout);
		if(size-ftell(fp)<16384){
			int lef = size-ftell(fp);
			fread(buf2, lef, 1, fp);
			fwrite(buf2, lef, 1, fpout);
			break;
		}else{
			fread(buf2, 16384, 1, fp);
			fwrite(buf2, 16384, 1, fpout);
		}
		//fputs("Encrypt\n", stdout);
	}
	
    fprintf(stdout, "Write %s success.\n",newfile);
	fclose(fp);
	fclose(fpout);
	return 0;
}
 
void Usage(){
	fprintf(stdout, "Usage:\n    zip2ozip [FILE] [CONFIG FILE]\n");
}

unsigned long long getfilesize(FILE *fp){
    unsigned long long  fz;
    fpos_t fpos; //当前位置
    fgetpos64(fp, &fpos); //获取当前位置
    fseeko64 (fp, 0L, SEEK_END);
    fz = ftello64(fp);
    fsetpos64(fp,&fpos); //恢复之前的位置
    return fz;
}

const char *readline(FILE *file) {

    if (file == NULL) {
        printf("Error: file pointer is null.");
        return NULL;
    }

    int maximumLineLength = 128;
    char *lineBuffer = (char *)malloc(sizeof(char) * maximumLineLength);

    if (lineBuffer == NULL) {
        printf("Error allocating memory for line buffer.");
        return NULL;
    }

    char ch = getc(file);
    int count = 0;

    while ((ch != '\n') && (ch != EOF)) {
        if (count == maximumLineLength) {
            maximumLineLength += 128;
            lineBuffer = realloc(lineBuffer, maximumLineLength);
            if (lineBuffer == NULL) {
                printf("Error reallocating space for line buffer.");
                return NULL;
            }
        }
        lineBuffer[count] = ch;
        count++;

        ch = getc(file);
    }

    lineBuffer[count] = '\0';
    char line[count + 1];
    strncpy(line, lineBuffer, (count + 1));
    free(lineBuffer);
    const char *constLine = line;
    return constLine;
}
/**
    写头部参数
    android_version=10
    google_patch=20210405
    os_version=V7.1
    ota-downgrade=no
    ota-id=PACM00_11.F.27_2270_202104251653
    ota-property-files=metadata:69:331
    ota-required-cache=0
    ota-type=BLOCK
    ota_version=PACM00_11.F.27_2270_202104251653
    patch_type=1
    post-timestamp=1619343001
    pre-device=PACM00
    version_name=PACM00_11_F.27
    wipe=0
*/
int writeheaderconfig(const char * filename,FILE *fp2){
    FILE * fp;
    char line [500];
    
    fp = fopen(filename, "r");
    if (fp == NULL)
        return -1;
    while(fgets(line,sizeof(line),fp)){
        //printf("%s",line);
        fprintf(fp2, "%s", line);
    }
    fclose(fp);
    return 0;
}