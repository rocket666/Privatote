/*********************************************************************/
/*-文件名：DES.c */
/*-版本号：v 0.0.0*/
/*-功能： 实现DES/TDES算法的加扰解扰功能*/
/*- */
/*********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "des.h"
#include "crypto_api_des.h"
#define SUCCESS 0 
#define FAIL -1

char  *DES_USE_HELP[]={
"输入39个参数:",
"\t 1.可执行文件名 *.exe",
"\t 2.模式 0：ecb trail clear; 1: dvs042; 2: ecb cts mode;3: ecb head clear; 4: cbc head clear; 5: cbc trail clear 6: cbc cts mdi; 7: cbc cts mdd; 8: rcbc cts mdi; 9: rcbc cts mdd "
"\t 3.算法选择 0:DES;  1:TDES;",
"\t 4.操作类型 0:加扰; 1:解扰;",
"\t 5.读出数据的文件名*.ts",
"\t 6.写入数据的文件名*.ts", 
"\t 7.PID号,16进制表示", 
"\t 8.KEY1第1个字节", 
"\t 9.KEY1第2个字节", 
"\t10.KEY1第3个字节", 
"\t11.KEY1第4个字节",
"\t12.KEY1第5个字节", 
"\t13.KEY1第6个字节", 
"\t14.KEY1第7个字节", 
"\t15.KEY1第8个字节", 
"\t16.KEY2第1个字节", 
"\t17.KEY2第2个字节", 
"\t18.KEY2第3个字节", 
"\t19.KEY2第4个字节",
"\t20.KEY2第5个字节", 
"\t21.KEY2第6个字节", 
"\t22.KEY2第7个字节", 
"\t23.KEY2第8个字节", 
"\t24.KEY3第1个字节", 
"\t25.KEY3第2个字节", 
"\t26.KEY3第3个字节", 
"\t27.KEY3第4个字节",
"\t28.KEY3第5个字节", 
"\t29.KEY3第6个字节", 
"\t30.KEY3第7个字节", 
"\t31.KEY3第8个字节", 
"\t32.IV第1个字节",
"\t32.IV第2个字节", 
"\t34.IV第3个字节", 
"\t35.IV第4个字节", 
"\t36.IV第5个字节", 
"\t37.IV第6个字节", 
"\t38.IV第7个字节", 
"\t39.IV第8个字节",
"\t例:des 0 0 1 1.ts 2.ts 0x203 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8    0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18    0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28  0xa 0xb 0xc 0xd 0x1 0x2 0x3 0x4 ",
"\t注意：PID号为13位数据必须为16进制小写表示,如 0x01ff，0x1010",
"\t所有输入的密钥数据必须为16进制小写表示,如 0x01 0xff",
"\t ******************************************************"
};

void des_print_help();
int file_des_tecb_enc (FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_tdes_tecb_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_ecb_cts_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_dvs042_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);
int file_tdes_hecb_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_hcbc_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);
int file_tdes_tcbc_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);
int file_des_tecb_dec (FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_tdes_tecb_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_ecb_cts_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_dvs042_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);
int file_tdes_hecb_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_hcbc_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);
int file_tdes_tcbc_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8]);

int file_des_cbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_cbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_rcbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_rcbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_cbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_cbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_rcbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_des_rcbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8]);
int file_tdes_cbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_cbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_rcbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_rcbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_cbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_cbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_rcbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);
int file_tdes_rcbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8]);



static void hexprint(unsigned char *hex, unsigned int len)
{
	unsigned int i = 0;
	for(i = 0; i < len; i ++)
	{
		if((i % 16) == 0)
			printf("\n");
		printf("%02x", hex[i]);
	}
	printf("\n");
}

int char2int(unsigned char low, unsigned char high)
{
	int low_int;
	int high_int;
	int out;
	if((low <= '9')&&(low >= '0'))
	{
		low_int = low - 48;
	}
	else if((low <= 'f')&&(low >= 'a'))
	{
		low_int = low - 87;
	}
	if((high <= '9')&&(high >= '0'))
	{
		high_int = high - 48;
	}
	else if((high <= 'f')&&(high >= 'a'))
	{
		high_int = high - 87;
	}
	out = (high_int * 16) + low_int;
	return out;
}

int main(int argc,char *argv[])
{
char *FILENAME1,*FILENAME2; 
FILE *fp, *fp2; 
unsigned char pid_tmp[2][4];
unsigned char pid[0x2];
unsigned char key1_tmp[8][4];
unsigned char key1[0x8]; 
unsigned char key2_tmp[8][4];
unsigned char key2[0x8]; 
unsigned char key3_tmp[8][4];
unsigned char key3[0x8]; 
unsigned char iv_tmp[8][4];       
unsigned char iv[0x8];            
int i,j;

if ( argc == 39 && (atoi(argv[1]) == 0 || atoi(argv[1]) == 1 || atoi(argv[1]) == 2 || atoi(argv[1]) == 3 || atoi(argv[1]) == 4 || atoi(argv[1]) == 5|| atoi(argv[1]) == 6 || atoi(argv[1]) == 7 || atoi(argv[1]) == 8 || atoi(argv[1]) == 9) && (atoi(argv[2]) == 0 || atoi(argv[2]) == 1 )&& (atoi(argv[3]) == 0 || atoi(argv[3]) == 1 ))
{
}
else
{
des_print_help();
return FAIL; 
}
FILENAME1 = argv[4];
FILENAME2 = argv[5];

if(strlen(argv[6]) == 6)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[6][2+j];
		pid_tmp[1][j] = argv[6][j+4];
		pid[0] = char2int(pid_tmp[0][3], pid_tmp[0][2]);		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[6]) == 5)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[6][2+j];
		pid_tmp[1][j] = argv[6][j+3];
		pid[0] = char2int(pid_tmp[0][2], '0');		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[6]) == 4)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[6][2+j];
		pid_tmp[1][j] = argv[6][j+2];
		pid[0] = char2int('0', '0');		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[6]) == 3)
{
	pid_tmp[0][2] = argv[6][2];
	pid_tmp[1][0] = argv[6][2];
	pid[0] = char2int('0', '0');		
	pid[1] = char2int(pid_tmp[1][0], '0');
}

for(i = 0; i < 8; i++)
{
	if (strlen(argv[7+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			key1_tmp[i][j] = argv[7 + i][j];
			key1[i] = char2int(key1_tmp[i][3], key1_tmp[i][2]);
	}
	else if (strlen(argv[7+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			key1_tmp[i][j] = argv[7 + i][j];
			key1[i] = char2int(key1_tmp[i][2], '0');
	}
	
	if (strlen(argv[15+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			key2_tmp[i][j] = argv[15 + i][j];
			key2[i] = char2int(key2_tmp[i][3], key2_tmp[i][2]);
	}
	else if (strlen(argv[15+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			key2_tmp[i][j] = argv[15 + i][j];
			key2[i] = char2int(key2_tmp[i][2], '0');
	}
	
	if (strlen(argv[23+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			key3_tmp[i][j] = argv[23 + i][j];
			key3[i] = char2int(key3_tmp[i][3], key3_tmp[i][2]);
	}
	else if (strlen(argv[23+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			key3_tmp[i][j] = argv[23 + i][j];
			key3[i] = char2int(key3_tmp[i][2], '0');
	}
	
	if (strlen(argv[31+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			iv_tmp[i][j] = argv[31 + i][j];
			iv[i] = char2int(iv_tmp[i][3], iv_tmp[i][2]);
	}
	else if (strlen(argv[31+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			iv_tmp[i][j] = argv[31 + i][j];
			iv[i] = char2int(iv_tmp[i][2], '0');
	}
}


printf("\n pid  = %02x %02x",pid[0],pid[1]);
printf("\n key1 = %02x %02x %02x %02x %02x %02x %02x %02x",key1[0],key1[1],key1[2],key1[3],key1[4],key1[5],key1[6],key1[7]);
printf("\n key2 = %02x %02x %02x %02x %02x %02x %02x %02x",key2[0],key2[1],key2[2],key2[3],key2[4],key2[5],key2[6],key2[7]);
printf("\n key3 = %02x %02x %02x %02x %02x %02x %02x %02x",key3[0],key3[1],key3[2],key3[3],key3[4],key3[5],key3[6],key3[7]);
printf("\n iv   = %02x %02x %02x %02x %02x %02x %02x %02x\n",iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7]);

if ((fp= fopen(FILENAME1,"rb")) == NULL || (fp2 = fopen(FILENAME2,"wb"))==NULL)
{ 

printf("Can't open file\n");
return FAIL;
}    

	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 0))
	{
		file_des_tecb_enc(fp,fp2,pid,key1);
		printf("\n \t DES ECB trail clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_tecb_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB trail clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else 
	if((atoi(argv[1])== 1) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_dvs042_enc(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES DVS042 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if ((atoi(argv[1])== 2) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_ecb_cts_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB CTS 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 3) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_hecb_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB head clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 4) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_hcbc_enc(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES CBC head clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 5) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_tcbc_enc(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES CBC trail clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 6) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 0))
	{
		file_des_cbc_cts_mdi_enc(fp,fp2,pid,key1);
		printf("\n \t  DES CBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 6) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_cbc_cts_mdi_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES CBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 7) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 0))
	{
		file_des_cbc_cts_mdd_enc(fp,fp2,pid,key1);
		printf("\n \t  DES CBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 7) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_cbc_cts_mdd_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES CBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 8) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 0))
	{
		file_des_rcbc_cts_mdi_enc(fp,fp2,pid,key1);
		printf("\n \t  DES RCBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 8) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_rcbc_cts_mdi_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES RCBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 9) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 0))
	{
		file_des_rcbc_cts_mdd_enc(fp,fp2,pid,key1);
		printf("\n \t  DES RCBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 9) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 0))
	{
		file_tdes_rcbc_cts_mdd_enc(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES RCBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 1))
	{
		file_des_tecb_dec(fp,fp2,pid,key1);
		printf("\n \t DES ECB trail clear 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_tecb_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB trail clear 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 1) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_dvs042_dec(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES DVS042 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if ((atoi(argv[1])== 2) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_ecb_cts_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB CTS 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 3) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_hecb_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t TDES ECB head clear 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 4) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_hcbc_dec(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES CBC head clear 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 5) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_tcbc_dec(fp,fp2,pid,key1,key2,key3,iv);
		printf("\n \t TDES CBC trail clear 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 6) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 1))
	{
		file_des_cbc_cts_mdi_dec(fp,fp2,pid,key1);
		printf("\n \t  DES CBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 6) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_cbc_cts_mdi_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES CBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 7) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 1))
	{
		file_des_cbc_cts_mdd_dec(fp,fp2,pid,key1);
		printf("\n \t  DES CBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}		
	else
	if((atoi(argv[1])== 7) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_cbc_cts_mdd_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES CBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 8) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 1))
	{
		file_des_rcbc_cts_mdi_dec(fp,fp2,pid,key1);
		printf("\n \t  DES RCBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}		
	else
	if((atoi(argv[1])== 8) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_rcbc_cts_mdi_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  DES RCBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 9) && (atoi(argv[2]) == 0)&& (atoi(argv[3]) == 1))
	{
		file_des_rcbc_cts_mdd_dec(fp,fp2,pid,key1);
		printf("\n \t  DES RCBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else
	if((atoi(argv[1])== 9) && (atoi(argv[2]) == 1)&& (atoi(argv[3]) == 1))
	{
		file_tdes_rcbc_cts_mdd_dec(fp,fp2,pid,key1,key2,key3);
		printf("\n \t  TDES RCBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}		
	else
		printf("请选择是DES加解扰模式配置\n"); 
		return FAIL;
}

void des_print_help()
{
int i ;
printf("\n");
for( i = 0 ; i < 44 ; i++)
{
printf("\t%s\n",DES_USE_HELP[i]);
}
return ;
}

int file_des_tecb_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 8;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_des_init(&des);
					c = &(des.c);
					c->set_key(c, key1, 0, 0, DES_DECRYPT);
					CRYPTO_API_des_ecb_decrypt(c, pt, 8);	
					for(k=offset;k<offset + 8;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 8;
					}
				for(j=offset;j<offset + trail;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_tecb_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 8;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_DECRYPT);
					CRYPTO_API_des_ecb_decrypt(c, pt, 8);	
					for(k=offset;k<offset + 8;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 8;
					}
				for(j=offset;j<offset + trail;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}


int file_tdes_ecb_cts_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if(N >= 1)
						{
							for(j=0;j<N;j++)											/* process N whole */
								{
								for(k=offset;k<offset+8;k++)
									{
									pt[k-offset] = buf[k] ;														
									}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(k=offset;k<offset+8;k++)
									{
									buf_o[k] = pt[k-offset];										
									}
								offset += 8;			
								}
																						/* process last N */		
							for(j =0; j< (8-trail);j++ )
								{
								pt[j] = buf_o[offset-8+trail+j];														
								}
							for(j =0; j< trail;j++ )
								{
								pt[8-trail+j] = buf[offset+j];
								}
							CRYPTO_API_tdes_init(&des);									/* last split process */
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_DECRYPT);
							CRYPTO_API_des_ecb_decrypt(c, pt, 8);
							for(j=8;j>0;j--)
								{
								buf_o[188-j] = pt[8-j];										
								}						
						}
						else															/* only payload < 8 */
						{
							for(j=0;j<trail;j++)
							{
							buf_o[offset+j] = buf[offset+j] ;
							}	
						}
					}
					else															  	/* trail = 0 */
					{
						for(j=0;j<N;j++)
							{
							for(k=offset;k<offset+8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_DECRYPT);
							CRYPTO_API_des_ecb_decrypt(c, pt, 8);
							for(k=offset;k<offset+8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;	
							}
					}
						
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_dvs042_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j;
	unsigned int offset=4;
	unsigned int payload_length=184;
	
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
		
	unsigned char pt[184];
	unsigned char iv_tmp[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for (j=0;j<8;j++)												//initial iv data every packet
		{
			iv_tmp[j] = iv[j];
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				payload_length = 184;
				
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				
				payload_length = 188 - offset;

				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
					
				for(j=0;j<payload_length;j++)
					{
					pt[j] = buf[j+offset] ;														
					}
				
				if(payload_length >= 8)													/* packet payload  >= whole  block */
					{
								
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_DECRYPT);
					c->buf = iv_tmp;
					CRYPTO_API_des_cbc_dvs042_decrypt(c, pt, payload_length);						
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset] ;										
						}			
					}
				else																	/* packet payload < whole  block  ?? */
					{
										
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					CRYPTO_API_des_ecb_encrypt(c, iv_tmp, 8);	
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset]^iv_tmp[j-offset] ;										
						}
					}						
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_hecb_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				offset += (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 8;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_DECRYPT);
					CRYPTO_API_des_ecb_decrypt(c, pt, 8);	
					for(k=offset;k<offset + 8;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 8;
					}
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_hcbc_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = iv[j];
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				if((buf[3] & 0x30) == 0x30)									/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8; 	
				offset += (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 8;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c,  key1, key2, key3, DES_DECRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_decrypt(c, pt, 8);						
					for(k=offset;k<offset + 8;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 8;
					}
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_tcbc_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = iv[j];
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if((buf[3] & 0x30) == 0x30)									/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8; 	
				trail = (188 - offset) % 8;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 8;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c,  key1, key2, key3, DES_DECRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_decrypt(c, pt, 8);						
					for(k=offset;k<offset + 8;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 8;
					}
				for(j=offset;j<offset + trail;j++)
						{
						buf_o[j] = buf[j] ;
						}
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_tecb_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					//packet cfg
					offset = 4;
					trail = 0;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8;
					trail = (188 - offset) % 8;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+8;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_des_init(&des);
						c = &(des.c);
						c->set_key(c, key1, 0, 0, DES_ENCRYPT);
						CRYPTO_API_des_ecb_encrypt(c, pt, 8);
						for(k=offset;k<offset+8;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 8;
					}
					for(j=offset;j<offset + trail;j++)
						{
						buf_o[j] = buf[j] ;
						}
					if(N !=0)
						buf_o[3] = buf_o[3] | 0x80;												/* add scrambling bits */	
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_tecb_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)													//pusi flag
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					//packet cfg
					offset = 4;
					trail = 0;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8;
					trail = (188 - offset) % 8;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+8;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_tdes_init(&des);
						c = &(des.c);
						c->set_key(c, key1, key2, key3, DES_ENCRYPT);
						CRYPTO_API_des_ecb_encrypt(c, pt, 8);
						for(k=offset;k<offset+8;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 8;
					}
					for(j=offset;j<offset + trail;j++)
						{
						buf_o[j] = buf[j] ;
						}
					if(N !=0)
						buf_o[3] = buf_o[3] | 0x80;												/* add scrambling bits */	
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_dvs042_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j;
	unsigned int offset=4;
	unsigned int payload_length=184;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
		
	unsigned char pt[184];
	unsigned char iv_tmp[8];
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		for (j=0;j<8;j++)
		{
			iv_tmp[j] = iv[j];															//initial iv data every packet
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
				
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */					
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */		
				//packet cfg
				offset = 4;
				
				if ((buf[3] & 0x30) == 0x30)
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}						
				payload_length = 188 - offset;
				
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
						
				for(j=0;j<payload_length;j++)
					{
					pt[j] = buf[j+offset] ;														
					}											
				if(payload_length >= 8)													/* packet payload  >= whole  block */
					{
								
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					c->buf = iv_tmp;
					CRYPTO_API_des_cbc_dvs042_encrypt(c, pt, payload_length);				
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset] ;										
						}			
					}
				else																	/* packet payload < whole  block */
					{
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					CRYPTO_API_des_ecb_encrypt(c, iv_tmp, 8);	
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset]^iv_tmp[j-offset] ;										
						}	
					}	
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_ecb_cts_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)													//pusi flag
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */		
					//packet cfg
					offset = 4;
					trail = 0;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8;
					trail = (188 - offset) % 8;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					if(trail > 0)
					{
						if(N >= 1)
						{
							for(j=0;j<N-1;j++)											/* process N whole */
								{
								for(k=offset;k<offset+8;k++)
									{
									pt[k-offset] = buf[k] ;														
									}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);																	
								for(k=offset;k<offset+8;k++)
									{
									buf_o[k] = pt[k-offset];										
									}
								offset += 8;			
								}
								
							for(j =0; j< 8;j++)											/* process the last N */	
								{
									pt[j] = buf[180+j];
								}
							CRYPTO_API_tdes_init(&des);									
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_ENCRYPT);
							CRYPTO_API_des_ecb_encrypt(c, pt, 8);
							for(j=0;j<8;j++)
								{
								buf_o[180+j] = pt[j];										
								}						
		
							for(j =0; j< trail;j++ )							 		/* split last N process */
								{
								pt[j] = buf[180-trail+j];														
								}
							for(j =0; j< (8-trail);j++ )
								{
								pt[trail+j] = buf_o[180+j];
								}
							CRYPTO_API_tdes_init(&des);									/* last split process */
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_ENCRYPT);
							CRYPTO_API_des_ecb_encrypt(c, pt, 8);
							for(j=0;j<8;j++)
								{
								buf_o[180-trail+j] = pt[j];										
								}					
						}
						else															/* only payload < 8 */
						{
							for(j=0;j<trail;j++)
							{
							buf_o[offset+j] = buf[offset+j] ;
							}	
						}
					}
					else															  	/* trail = 0 */
					{
						for(j=0;j<N;j++)
							{
							for(k=offset;k<offset+8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_ENCRYPT);
							CRYPTO_API_des_ecb_encrypt(c, pt, 8);
							for(k=offset;k<offset+8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;	
							}
					}
															
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_hecb_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)													//pusi flag
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					//packet cfg
					offset = 4;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8;
					offset += (188 - offset) % 8;
			
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+8;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_tdes_init(&des);
						c = &(des.c);
						c->set_key(c, key1, key2, key3, DES_ENCRYPT);
						CRYPTO_API_des_ecb_encrypt(c, pt, 8);
						for(k=offset;k<offset+8;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 8;
					}					
					if(N !=0)
						buf_o[3] = buf_o[3] | 0x80;												/* add scrambling bits */	
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_hcbc_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = iv[j];
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)													/* pusi flag packet */
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					//packet cfg
					offset = 4;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8; 					
					offset += (188 - offset) % 8;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+8;k++)
							{
							pt[k-offset] = buf[k] ;														
							}					
						CRYPTO_API_tdes_init(&des);
						c = &(des.c);
						c->set_key(c, key1, key2, key3, DES_ENCRYPT);
						c->buf = ive;
						CRYPTO_API_des_cbc_encrypt(c, pt, 8);																
						for(k=offset;k<offset+8;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 8;
					}
					if(N !=0)
						buf_o[3] = buf_o[3] | 0x80;												/* add scrambling bits */	
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}								
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_tcbc_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8],unsigned char iv[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];

	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = iv[j];
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
//				if((buf[1]&0x40) == 0x40)													  //pusi flag
//					buf[3] = buf[3];
//				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
//				if((buf[1]&0x40) == 0x40)													/* pusi flag packet */
//				{
//					for (j=0;j<188;j++)								
//					{
//						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
//					}
//				}
//				else
				{
					//packet cfg
					offset = 4;
					trail  = 0;
					if ((buf[3] & 0x30) == 0x30)
						{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
							}
						}	
					N = (188 - offset) / 8; 					
					trail = (188 - offset) % 8;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+8;k++)
							{
							pt[k-offset] = buf[k] ;														
							}					
						CRYPTO_API_tdes_init(&des);
						c = &(des.c);
						c->set_key(c, key1, key2, key3, DES_ENCRYPT);
						c->buf = ive;
						CRYPTO_API_des_cbc_encrypt(c, pt, 8);																
						for(k=offset;k<offset+8;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 8;
					}
					for(j=offset;j<offset + trail;j++)
						{
						buf_o[j] = buf[j] ;
						}
					if(N !=0)
						buf_o[3] = buf_o[3] | 0x80;												/* add scrambling bits */	
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}								
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_cbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;
				hexprint(ive,8);													
				CRYPTO_API_des_init(&des);												/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, 0, 0, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
				hexprint(ive,8);			
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)										/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_des_init(&des);
									c = &(des.c);
									c->set_key(c, key1, 0, 0, DES_ENCRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
							
									for(k=0;k<8;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 8;
								}												
								if(N >= 2)
									{
									for(j=0;j<8;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-8+j] ;	
										}
									offset += 8;	
									}
								else
									{
									for(j=0;j<8;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 8;		
									}								
								CRYPTO_API_des_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);				
															
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)									/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}															
								CRYPTO_API_des_init(&des);											
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
				
								for(j=0;j<8;j++)
									{
									buf_o[offset-8+j]= pt[j];
									}																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}							
							CRYPTO_API_des_init(&des);
							c = &(des.c);
							c->set_key(c, key1, 0, 0, DES_ENCRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
									
														
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}			
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_cbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;														
				CRYPTO_API_tdes_init(&des);												/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, key2, key3, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
				
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)										/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_tdes_init(&des);
									c = &(des.c);
									c->set_key(c, key1, key2, key3, DES_ENCRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
							
									for(k=0;k<8;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 8;
								}												
								if(N >= 2)
									{
									for(j=0;j<8;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-8+j] ;	
										}
									offset += 8;	
									}
								else
									{
									for(j=0;j<8;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 8;		
									}								
								CRYPTO_API_tdes_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, ive, 8);				
															
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)									/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}															
								CRYPTO_API_tdes_init(&des);											
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, ive, 8);
				
								for(j=0;j<8;j++)
									{
									buf_o[offset-8+j]= pt[j];
									}																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}							
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_ENCRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
									
														
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}			
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_cbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   	// no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
				buf[3] = buf[3] | 0x80;													  		/* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				buf[3] = buf[3] | 0x80;													  		/* add scrambling bits */	
				/* for scl value calculate IVE must first set */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;
				hexprint(ive,8);																	
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_des_init(&des);
					c = &(des.c);
					c->set_key(c, key1, 0, 0, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
												
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				hexprint(ive,8);			
				//start enc		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)											/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}								
									CRYPTO_API_des_init(&des);
									c = &(des.c);
									c->set_key(c, key1, 0, 0, DES_ENCRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
											
									for(k=0;k<8;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 8;
								}												
								if(N >= 2)
									{
									for(j=0;j<8;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-8+j] ;	
										}
									offset += 8;	
									}
								else
									{
									for(j=0;j<8;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 8;		
									}								
								CRYPTO_API_des_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);		
																
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}															
								CRYPTO_API_des_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);		
								
								for(j=0;j<8;j++)
									{
									buf_o[offset-8+j]= pt[j];
									}																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}							
							CRYPTO_API_des_init(&des);
							c = &(des.c);
							c->set_key(c, key1, 0, 0, DES_ENCRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
																
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}			
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_cbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   	// no payload 
			{
				printf("\n no payload packet!!! ");
				printf("packet_num = %d",i+1);
				buf[3] = buf[3] | 0x80;													  		/* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				buf[3] = buf[3] | 0x80;													  		/* add scrambling bits */	
				/* for scl value calculate IVE must first set */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;														
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
												
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				
				//start enc		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)											/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}								
									CRYPTO_API_tdes_init(&des);
									c = &(des.c);
									c->set_key(c, key1, key2, key3, DES_ENCRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
											
									for(k=0;k<8;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 8;
								}												
								if(N >= 2)
									{
									for(j=0;j<8;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-8+j] ;	
										}
									offset += 8;	
									}
								else
									{
									for(j=0;j<8;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 8;		
									}								
								CRYPTO_API_tdes_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, ive, 8);		
																
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}															
								CRYPTO_API_tdes_init(&des);												
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, ive, 8);		
								
								for(j=0;j<8;j++)
									{
									buf_o[offset-8+j]= pt[j];
									}																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 16;k++)
								{
								pt[k-offset] = buf[k] ;														
								}							
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_ENCRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
																
							for(k=offset;k<offset + 16;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 16;
						}		
					}			
				for (j=0;j<188;j++)
				{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
				}									
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_rcbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive_tmp[8];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] = buf[3] | 0x80;													  	 /* add scrambling bits */	
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}												
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] = buf[3] | 0x80;										/* add scrambling bits */	
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}		
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																					
				CRYPTO_API_des_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, 0, 0, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
	
//				hexprint(ive,16);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<8;j++)											/* IVE initial */
					{
						ive_tmp[j]=ive[j];
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_des_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
					
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}										
										CRYPTO_API_des_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_des_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+2)*8+j]^pt[j];	
													}											
													CRYPTO_API_des_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
//													hexprint(buf_o,188);
												}									
										}										
									}
								else
									{
										N= N+1;
										for(j=0;j<N-2;j++)											/* process last N-2 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}												
										for(j=0;j<8;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_des_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										for(j=0;j<8;j++)
											{
												buf_o[188-16-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_des_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
														
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_des_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_des_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+3)*8+j]^pt[j];	
													}											
													CRYPTO_API_des_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);	
												}									
										}											
									}
							}
						else
							{
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j] = buf[offset+j]^ive_tmp[j] ;
									}
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_des_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_des_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(8-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(16-j)]^pt[j];	
								}
								CRYPTO_API_des_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_des_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(24-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_des_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+4)*8+j]^pt[j];	
											}											
											CRYPTO_API_des_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);	
										}									
								}																																																																																																																																							
							}
						else																		/* N is even */
							{
								while(round < N)
								{									
									if(round_flag)
										{
											for(j=0;j<N-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_des_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+1)*8+j]^pt[j];	
											}											
											CRYPTO_API_des_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}	
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_decrypted );
	fclose ( file_encrypted );
	return SUCCESS;
}

int file_tdes_rcbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive_tmp[8];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] = buf[3] | 0x80;													  	 /* add scrambling bits */	
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}												
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] = buf[3] | 0x80;										/* add scrambling bits */	
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}		
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																					
				CRYPTO_API_tdes_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, key2, key3, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
	
//				hexprint(ive,16);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<8;j++)											/* IVE initial */
					{
						ive_tmp[j]=ive[j];
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_tdes_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
					
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}										
										CRYPTO_API_tdes_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_tdes_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+2)*8+j]^pt[j];	
													}											
													CRYPTO_API_tdes_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
//													hexprint(buf_o,188);
												}									
										}										
									}
								else
									{
										N= N+1;
										for(j=0;j<N-2;j++)											/* process last N-2 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}												
										for(j=0;j<8;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_tdes_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										for(j=0;j<8;j++)
											{
												buf_o[188-16-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_tdes_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
														
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_tdes_init(&des);									
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_tdes_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+3)*8+j]^pt[j];	
													}											
													CRYPTO_API_tdes_init(&des);									
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);	
												}									
										}											
									}
							}
						else
							{
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j] = buf[offset+j]^ive_tmp[j] ;
									}
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_tdes_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_tdes_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(8-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(16-j)]^pt[j];	
								}
								CRYPTO_API_tdes_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_tdes_init(&des);									
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[188-(24-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_tdes_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+4)*8+j]^pt[j];	
											}											
											CRYPTO_API_tdes_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);	
										}									
								}																																																																																																																																							
							}
						else																		/* N is even */
							{
								while(round < N)
								{									
									if(round_flag)
										{
											for(j=0;j<N-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_tdes_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+1)*8+j]^pt[j];	
											}											
											CRYPTO_API_tdes_init(&des);									
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}	
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_decrypted );
	fclose ( file_encrypted );
	return SUCCESS;
}

int file_des_rcbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive_tmp[8];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] = buf[3] | 0x80;													  	 /* add scrambling bits */	
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}												
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] = buf[3] | 0x80;										/* add scrambling bits */	
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																	
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_des_init(&des);
					c = &(des.c);
					c->set_key(c, key1, 0, 0, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);							
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
//				hexprint(ive,8);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<8;j++)											/* IVE initial */
					{
						ive_tmp[j]=ive[j];
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);																					
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}																						
													CRYPTO_API_des_init(&des);
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+2)*8+j]^pt[j];	
													}											
													CRYPTO_API_des_init(&des);
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
//													hexprint(buf_o,188);
												}									
										}										
									}
								else
									{
										N= N+1;
										for(j=0;j<N-2;j++)											/* process last N-2 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}												
										for(j=0;j<8;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<8;j++)
											{
												buf_o[188-16-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);
										c->set_key(c, key1, 0, 0, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_des_init(&des);
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+3)*8+j]^pt[j];	
													}											
													CRYPTO_API_des_init(&des);
													c = &(des.c);
													c->set_key(c, key1, 0, 0, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);	
												}									
										}											
									}
							}
						else
							{
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j] = buf[offset+j]^ive_tmp[j] ;
									}
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_des_init(&des);
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(8-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(16-j)]^pt[j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);
								c->set_key(c, key1, 0, 0, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(24-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+4)*8+j]^pt[j];	
											}											
											CRYPTO_API_des_init(&des);
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);	
										}									
								}																																																																																																																																							
							}
						else																		/* N is even */
							{
								while(round < N)
								{									
									if(round_flag)
										{
											for(j=0;j<N-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+1)*8+j]^pt[j];	
											}											
											CRYPTO_API_des_init(&des);
											c = &(des.c);
											c->set_key(c, key1, 0, 0, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);		
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}	
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_decrypted );
	fclose ( file_encrypted );
	return SUCCESS;
}

int file_tdes_rcbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive_tmp[8];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] = buf[3] | 0x80;													  	 /* add scrambling bits */	
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}												
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] = buf[3] | 0x80;										/* add scrambling bits */	
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
						printf("\n this packet af length is wrong  ");
						printf("packet_num = %d\n",i+1);
						offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																	
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);							
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
//				hexprint(ive,8);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<8;j++)											/* IVE initial */
					{
						ive_tmp[j]=ive[j];
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);																					
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}																						
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+2)*8+j]^pt[j];	
													}											
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+2)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
//													hexprint(buf_o,188);
												}									
										}										
									}
								else
									{
										N= N+1;
										for(j=0;j<N-2;j++)											/* process last N-2 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}												
										for(j=0;j<8;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<8;j++)
											{
												buf_o[188-16-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<8;j++)											
											{
												pt[j] = buf[188-8-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);
										c->set_key(c, key1, key2, key3, DES_ENCRYPT);
										CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<8;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
														}
													}
													for(j=0;j<8;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[188-trail-(round+3)*8+j]^pt[j];	
													}											
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);
													c->set_key(c, key1, key2, key3, DES_ENCRYPT);
													CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[188-trail-(round+3)*8+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);	
												}									
										}											
									}
							}
						else
							{
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j] = buf[offset+j]^ive_tmp[j] ;
									}
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(8-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(16-j)]^pt[j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<8;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
									}
								}
								for(j=0;j<8;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);
								c->set_key(c, key1, key2, key3, DES_ENCRYPT);
								CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
								for(j=0;j<8;j++)
								{
									buf_o[188-(24-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+4)*8+j]^pt[j];	
											}											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+4)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);	
										}									
								}																																																																																																																																							
							}
						else																		/* N is even */
							{
								while(round < N)
								{									
									if(round_flag)
										{
											for(j=0;j<N-round;j++)
											{
												for(k=0;k<8;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*8+k];		
												}
											}
											for(j=0;j<8;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);	
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[188-(round+1)*8+j]^pt[j];	
											}											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);
											c->set_key(c, key1, key2, key3, DES_ENCRYPT);
											CRYPTO_API_des_ecb_encrypt(c, pt, 8);		
											for(j=0;j<8;j++)
											{
												buf_o[188-(round+1)*8+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}	
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
		}
	}
	fclose ( file_decrypted );
	fclose ( file_encrypted );
	return SUCCESS;
}

int file_des_cbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
								printf("\n this packet af length is wrong  ");
								printf("packet_num = %d\n",i+1);
								offset = 188;
							}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;
				hexprint(ive,8);																	
				CRYPTO_API_des_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, 0, 0, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);	
				hexprint(ive,8);										
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)							/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_des_init(&des);
									c = &(des.c);
									c->set_key(c,  key1, 0, 0, DES_DECRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);
								
									for(k=offset;k<offset + 8;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 8;
								}
								for(j=0;j<8;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 8;								
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								if(N >= 2)
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^buf[188-trail-16+j];
										}
									}
								else
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^ive[j];
										}
									}
																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_des_init(&des);
							c = &(des.c);
							c->set_key(c,  key1, 0, 0, DES_DECRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);						
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_cbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
								printf("\n this packet af length is wrong  ");
								printf("packet_num = %d\n",i+1);
								offset = 188;
							}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;														
				CRYPTO_API_tdes_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, key2, key3, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);								
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)							/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_tdes_init(&des);
									c = &(des.c);
									c->set_key(c, key1, key2, key3, DES_DECRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);
								
									for(k=offset;k<offset + 8;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 8;
								}
								for(j=0;j<8;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 8;								
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								if(N >= 2)
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^buf[188-trail-16+j];
										}
									}
								else
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^ive[j];
										}
									}
																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c, key1, key2, key3, DES_DECRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);						
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_cbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{			
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
								printf("\n this packet af length is wrong  ");
								printf("packet_num = %d\n",i+1);
								offset = 188;
							}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;
				hexprint(ive,8);
				printf("ive = \n");			
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)										/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}
					hexprint(pt,8);	
					printf("data = \n");						
					CRYPTO_API_des_init(&des);
					c = &(des.c);
					c->set_key(c, key1, 0, 0, DES_ENCRYPT);
					c->buf = ive;
					hexprint(key1,8);	
					printf("key1 = \n");		
					hexprint(ive,8);
					printf("ive = \n");		
					
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);							
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				hexprint(ive,8);			
				//start descramble	
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */											
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)							/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_des_init(&des);
									c = &(des.c);
									c->set_key(c,  key1, 0, 0, DES_DECRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);
								
									for(k=offset;k<offset + 8;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 8;
								}
								for(j=0;j<8;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 8;								
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								if(N >= 2)
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^buf[188-trail-16+j];
										}
									}
								else
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^ive[j];
										}
									}
																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}								
							CRYPTO_API_des_init(&des);
							c = &(des.c);
							c->set_key(c,  key1, 0, 0, DES_DECRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);					
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_cbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
	unsigned char ive[8];
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		for(j=0;j<8;j++)
		{
			ive[j] = 0x0;
		}
		ive[3] = 0xbc;
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{			
				//packet cfg
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
						offset += (buf[4] +1);  
						if(offset > 188)
							{
								printf("\n this packet af length is wrong  ");
								printf("packet_num = %d\n",i+1);
								offset = 188;
							}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;
				
				ive[7] = offset;
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)										/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);							
					}	
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				
				//start descramble	
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */											
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				
				if(trail > 0)
					{
						if( N >= 1)
							{
								for(j=0;j<N-1;j++)							/* N -1 block process */
								{
									for(k=offset;k<offset + 8;k++)
										{
										pt[k-offset] = buf[k] ;														
										}									
									CRYPTO_API_tdes_init(&des);
									c = &(des.c);
									c->set_key(c,  key1, key2, key3, DES_DECRYPT);
									c->buf = ive;
									CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);
								
									for(k=offset;k<offset + 8;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 8;
								}
								for(j=0;j<8;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 8;								
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								if(N >= 2)
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^buf[188-trail-16+j];
										}
									}
								else
									{
										for(j=0;j<8;j++)
										{
										buf_o[188-trail-8+j]= pt[j]^ive[j];
										}
									}
																
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[188-trail+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{
						for(j=0;j<N;j++)
						{
							for(k=offset;k<offset + 8;k++)
								{
								pt[k-offset] = buf[k] ;														
								}								
							CRYPTO_API_tdes_init(&des);
							c = &(des.c);
							c->set_key(c,  key1, key2, key3, DES_DECRYPT);
							c->buf = ive;
							CRYPTO_API_des_cbc_cts_decrypt(c, pt, 8);					
							for(k=offset;k<offset + 8;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 8;
						}		
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_rcbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
//	unsigned char ive[16];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																				
				CRYPTO_API_des_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, 0, 0, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
	
				//start dec packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										while(round < N-2)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																										
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<8;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);										
									}									
								else
									{
										N= N+1;
										while(round < N-3)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																										
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
														
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<8;j++)													/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<8;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 8;
										for(j=0;j<16;j++)													/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}										
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
														
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)												/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);	
										
									}															
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[offset+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;		
								}									
							}
						else if( (N%2)==1 )																/* N is odd and >=3 */
							{															
								while(round < N-3)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<8;j++)													/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 8;
								
								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+8+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 8;
								
								for(j=0;j<8;j++)													/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;			
								}																								
							}
						else																		/* N is even */
							{
								while(round < N)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}											
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_rcbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
//	unsigned char ive[16];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																				
				CRYPTO_API_tdes_init(&des);									/* calculate IVE	*/
				c = &(des.c);
				c->set_key(c, key1, key2, key3, DES_ENCRYPT);
				CRYPTO_API_des_ecb_encrypt(c, ive, 8);
	
				//start dec packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;										
										while(round < N-2)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																										
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<8;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1,key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);										
									}									
								else
									{
										N= N+1;
										while(round < N-3)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																										
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
														
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<8;j++)													/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													
										for(j=0;j<8;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 8;
										for(j=0;j<16;j++)													/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}										
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1,key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
														
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)												/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);	
										
									}															
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[offset+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1,key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;		
								}									
							}
						else if( (N%2)==1 )																/* N is odd and >=3 */
							{															
								while(round < N-3)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1,key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<8;j++)													/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1,key2, key3,DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 8;
								
								for(j=0;j<8;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1,key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+8+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 8;
								
								for(j=0;j<8;j++)													/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;			
								}																								
							}
						else																		/* N is even */
							{
								while(round < N)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1,key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}											
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_des_rcbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
//	unsigned char ive[8];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{			
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
				
				/* for scl value calculate IVE must first set */
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)											/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_des_init(&des);
					c = &(des.c);
					c->set_key(c, key1, 0, 0, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
								
					}
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				//start dec packet	
				buf[3] &= 0x3f; 									 			/* remove scrambling bits */	
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;
										while(round < N-2)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<8;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);										
									}									
								else
									{
										N= N+1;
										while(round < N-3)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_des_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, 0, 0, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<8;j++)												/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 8;
										for(j=0;j<8;j++)												/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)											/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_des_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, 0, 0, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);	
										
									}															
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[offset+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;		
								}									
							}
						else if( (N%2)==1 )																/* N is odd and >=3 */
							{															
								while(round < N-3)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<8;j++)														/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 8;
								
								for(j=0;j<8;j++)														/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+8+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 8;
								
								for(j=0;j<8;j++)														/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_des_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, 0, 0, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;			
								}																								
							}
						else																			/* N is even */
							{
								while(round < N)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_des_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, 0, 0, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}			
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_tdes_rcbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key1[0x8],unsigned char key2[0x8],unsigned char key3[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_DES_CONTEX des;
	PCRYPTO_DES_BLOCK_CIPHER c = 0; 
	unsigned char pt[8];
//	unsigned char ive[8];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[8] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x30)==0x20) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   /* no payload */
			{
				printf("\n no payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{			
				//packet cfg
				round = 0;
				round_flag=1;
				offset = 4;
				trail = 0;
				if ((buf[3] & 0x30) == 0x30)								/* 0-182 AF data */
					{
					offset += (buf[4] +1);  
					if(offset > 188)
						{
							printf("\n this packet af length is wrong  ");
							printf("packet_num = %d\n",i+1);
							offset = 188;
						}
					}	
				N = (188 - offset) / 8;
				trail = (188 - offset) % 8;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
				
				/* for scl value calculate IVE must first set */
				if(offset % 8)						
					ive_offset = offset/8 + 1;
				else
					ive_offset = offset/8;					
				ive_offset = ive_offset * 8;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/8);j++)
					{
					for(k=0;k<8;k++)											/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*8 + k] ;														
						}					
					CRYPTO_API_tdes_init(&des);
					c = &(des.c);
					c->set_key(c, key1, key2, key3, DES_ENCRYPT);
					c->buf = ive;
					CRYPTO_API_des_cbc_cts_encrypt(c, pt, 8);
								
					}
					
				for(j=0;j<8;j++)		
					{
					ive[j]=	pt[j];
					}
				//start dec packet	
				buf[3] &= 0x3f; 									 			/* remove scrambling bits */	
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}					
				if(trail > 0)
					{
						if( N >= 1)
							{
								if( (N%2)==1 )	
									{
										N= N+1;
										while(round < N-2)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}																						
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1,  key2, key3,DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<8;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1,key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);										
									}									
								else
									{
										N= N+1;
										while(round < N-3)
										{
											if(round_flag)
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);	
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+8+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 8;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<8;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_tdes_init(&des);
													c = &(des.c);	
													c->set_key(c, key1, key2, key3, DES_DECRYPT);
													CRYPTO_API_des_ecb_decrypt(c, pt, 8);
													for(j=0;j<8;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 8;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<8;j++)												/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 8;
										for(j=0;j<8;j++)												/* process last N-1 block */
										{
											pt[j] = buf[188-8-trail+j];
										}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1, key2, key3,DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<trail;j++)
										{
											buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
											ive[j]= ive[j]^buf_o[188-trail+j];
										}
//										hexprint(buf_o,188);
										for(j=0;j<trail;j++)											/* process trail block */
											{
												pt[j] = buf[188-trail+j];
											}
										CRYPTO_API_tdes_init(&des);
										c = &(des.c);	
										c->set_key(c, key1,key2, key3, DES_DECRYPT);
										CRYPTO_API_des_ecb_decrypt(c, pt, 8);
										for(j=0;j<8;j++)
										{
											buf_o[188-8-trail+j] = pt[j]^ive[j];
										}
//										hexprint(buf_o,188);	
										
									}															
							}
						else
							{
								for(j = 0; j< trail;j++ )
								{
								buf_o[offset+j] = buf[offset+j]^ive[j];
								}	
							}
					}
				else
					{				
						if( N == 1 )
							{
								for(j=0;j<8;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1,key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;		
								}									
							}
						else if( (N%2)==1 )																/* N is odd and >=3 */
							{															
								while(round < N-3)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3,DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<8;j++)														/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 8;
								
								for(j=0;j<8;j++)														/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1,key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+8+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 8;
								
								for(j=0;j<8;j++)														/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_tdes_init(&des);
								c = &(des.c);	
								c->set_key(c, key1, key2, key3, DES_DECRYPT);
								CRYPTO_API_des_ecb_decrypt(c, pt, 8);
								for(j=0;j<8;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;			
								}																								
							}
						else																			/* N is even */
							{
								while(round < N)
								{
									if(round_flag)
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3, DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+8+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 8;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<8;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_tdes_init(&des);
											c = &(des.c);	
											c->set_key(c, key1, key2, key3,DES_DECRYPT);
											CRYPTO_API_des_ecb_decrypt(c, pt, 8);
											for(j=0;j<8;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 8;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}			
							}																			
					}
				
				for (j=0;j<188;j++)
					{
					fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}				
			}
			else
			{
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}
			}
		}
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}