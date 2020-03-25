/*********************************************************************/
/*-文件名：AES.c */
/*-版本号：v 0.0.0*/
/*-功能： 实现AES算法的加扰解扰功能*/
/*- */
/*********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "crypto_api_aes.h"
#define SUCCESS 0 
#define FAIL -1

char  *AES_USE_HELP[]={
"输入38个参数:",
"\t 1.可执行文件名 *.exe",
"\t 2.AES 模式 0：ecb head clear; 1：ecb trail clear; 2: cbc head clear for Marlin; 3: cbc trail clear for Marlin; 4: cbc cts mdi; 5: cbc cts mdd; 6: rcbc cts mdi; 7: rcbc cts mdd;8:cbc cts all;9: rcbc cts all; 10：cbc dvs042 for Marlin 11: ecb cts mode"
"\t 3.操作类型 0:加扰;  1:解扰;",
"\t 4.读出数据的文件名*.ts",
"\t 5.写入数据的文件名*.ts", 
"\t 6.PID号,16进制表示",  
"\t 7.密钥第1个字节", 
"\t 8.密钥第2个字节", 
"\t 9.密钥第3个字节", 
"\t10.密钥第4个字节", 
"\t11.密钥第5个字节",
"\t12.密钥第6个字节", 
"\t13.密钥第7个字节", 
"\t14.密钥第8个字节", 
"\t15.密钥第9个字节", 
"\t16.密钥第10个字节", 
"\t17.密钥第11个字节", 
"\t18.密钥第12个字节", 
"\t19.密钥第13个字节", 
"\t20.密钥第14个字节", 
"\t21.密钥第15个字节", 
"\t22.密钥第16个字节", 
"\t23.IV第1个字节",
"\t24.IV第2个字节", 
"\t25.IV第3个字节", 
"\t26.IV第4个字节", 
"\t27.IV第5个字节", 
"\t28.IV第6个字节", 
"\t29.IV第7个字节", 
"\t30.IV第8个字节",
"\t31.IV第9个字节", 
"\t32.IV第10个字节", 
"\t33.IV第11个字节", 
"\t34.IV第12个字节",
"\t35.IV第13个字节", 
"\t36.IV第14个字节", 
"\t37.IV第15个字节",
"\t38.IV第16个字节", 
"\t例:aes 0 2 1.ts 2.ts 0x203 0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06 0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
"\t注意：PID号为13位数据必须为16进制小写表示,如 0x01ff，0x1010",
"\t所有输入的密钥数据必须为16进制小写表示,如 0x01 0xff",
"\t ******************************************************"
};

void aes_print_help();
int file_aes_hecb_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_tecb_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_hecb_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_tecb_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_hcbc_Marlin_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_tcbc_Marlin_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_hcbc_Marlin_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_tcbc_Marlin_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_cbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_cbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_cbc_cts_all_enc(FILE *readfile,FILE *writefile,unsigned char key[0x10]);
int file_aes_rcbc_cts_mdi_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_rcbc_cts_mdd_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_rcbc_cts_all_enc(FILE *readfile,FILE *writefile,unsigned char key[0x10]);
int file_aes_cbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_cbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_cbc_cts_all_dec(FILE *readfile,FILE *writefile,unsigned char key[0x10]);
int file_aes_rcbc_cts_mdi_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_rcbc_cts_mdd_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_rcbc_cts_all_dec(FILE *readfile,FILE *writefile,unsigned char key[0x10]);
int file_aes_dvs042_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_dvs042_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10]);
int file_aes_ecb_cts_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);
int file_aes_ecb_cts_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],unsigned char key[0x10]);


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
unsigned char key_tmp[16][4];
unsigned char key[0x10]; 
unsigned char iv_tmp[16][4];       
unsigned char iv[0x10];            
int i,j;

if ( argc == 38 && (atoi(argv[1]) == 0 || atoi(argv[1]) == 1 || atoi(argv[1]) == 2|| atoi(argv[1]) == 3|| atoi(argv[1]) == 4|| atoi(argv[1]) == 5|| atoi(argv[1]) == 6|| atoi(argv[1]) == 7|| atoi(argv[1]) == 8|| atoi(argv[1]) == 9|| atoi(argv[1]) == 10 || atoi(argv[1]) == 11) &&(atoi(argv[2]) == 0 || atoi(argv[2]) == 1 ))
{
}
else
{
aes_print_help();
return FAIL; 
}
FILENAME1 = argv[3];
FILENAME2 = argv[4];

if(strlen(argv[5]) == 6)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[5][2+j];
		pid_tmp[1][j] = argv[5][j+4];
		pid[0] = char2int(pid_tmp[0][3], pid_tmp[0][2]);		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[5]) == 5)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[5][2+j];
		pid_tmp[1][j] = argv[5][j+3];
		pid[0] = char2int(pid_tmp[0][2], '0');		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[5]) == 4)
{
	for(j = 0; j < 2; j++)
	{
		pid_tmp[0][2+j] = argv[5][2+j];
		pid_tmp[1][j] = argv[5][j+2];
	}
	pid[0] = char2int('0', '0');		
	pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
}
else if (strlen(argv[5]) == 3)
{
	pid_tmp[0][2] = argv[5][2];
	pid_tmp[1][0] = argv[5][2];
	pid[0] = char2int('0', '0');		
	pid[1] = char2int(pid_tmp[1][0], '0');
}

for(i = 0; i < 16; i++)
{
	if (strlen(argv[6+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			key_tmp[i][j] = argv[6 + i][j];
			key[i] = char2int(key_tmp[i][3], key_tmp[i][2]);
	}
	else if (strlen(argv[6+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			key_tmp[i][j] = argv[6 + i][j];
			key[i] = char2int(key_tmp[i][2], '0');
	}
}

for(i = 0; i < 16; i++)
{
	if (strlen(argv[22+i]) == 4)
	{
		for(j = 2; j < 4; j++)
			iv_tmp[i][j] = argv[22 + i][j];
			iv[i] = char2int(iv_tmp[i][3], iv_tmp[i][2]);
	}
	else if (strlen(argv[22+i]) == 3)
	{
		for(j = 2; j < 3; j++)
			iv_tmp[i][j] = argv[22 + i][j];
			iv[i] = char2int(iv_tmp[i][2], '0');
	}
}

printf("\n pid  = %02x %02x",pid[0],pid[1]);
printf("\n cw   = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],key[8],key[9],key[10],key[11],key[12],key[13],key[14],key[15]);
printf("\n iv   = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);

if ((fp= fopen(FILENAME1,"rb")) == NULL || (fp2 = fopen(FILENAME2,"wb"))==NULL)
{ 

printf("Can't open file\n");
return FAIL;
}    

	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 0))
	{
		file_aes_hecb_enc(fp,fp2,pid,key);
		printf("\n \t AES ECB head clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 1) && (atoi(argv[2]) == 0))
	{
		file_aes_tecb_enc(fp,fp2,pid,key);
		printf("\n \t AES ECB trail clear 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 2) && (atoi(argv[2]) == 0))
	{
		file_aes_hcbc_Marlin_enc(fp,fp2,pid,key,iv);
		printf("\n \t AES CBC head clear for Marlin 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
	if((atoi(argv[1])== 3) && (atoi(argv[2]) == 0))
	{
		file_aes_tcbc_Marlin_enc(fp,fp2,pid,key,iv);
		printf("\n \t AES CBC trail clear for Marlin 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 4) && (atoi(argv[2]) == 0))
	{
		file_aes_cbc_cts_mdi_enc(fp,fp2,pid,key); 
		printf("\n \t  AES CBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 5) && (atoi(argv[2]) == 0))
	{
		file_aes_cbc_cts_mdd_enc(fp,fp2,pid,key); 
		printf("\n \t  AES CBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 6) && (atoi(argv[2]) == 0))
	{
		file_aes_rcbc_cts_mdi_enc(fp,fp2,pid,key); 
		printf("\n \t  AES RCBC CTS MDI for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 7) && (atoi(argv[2]) == 0))
	{
		file_aes_rcbc_cts_mdd_enc(fp,fp2,pid,key); 
		printf("\n \t  AES RCBC CTS MDD for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 8) && (atoi(argv[2]) == 0))
	{
		file_aes_cbc_cts_all_enc(fp,fp2,key); 
		printf("\n \t  AES CBC CTS ALL for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 9) && (atoi(argv[2]) == 0))
	{
		file_aes_rcbc_cts_all_enc(fp,fp2,key); 
		printf("\n \t  AES RCBC CTS ALL for ETSI 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 10) && (atoi(argv[2]) == 0))
	{
		file_aes_dvs042_enc(fp,fp2,pid,key,iv); 
		printf("\n \t  AES DVS042 for Marlin 加扰完毕,密文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else  
	if ((atoi(argv[1])== 11) && (atoi(argv[2]) == 0))
	{
		file_aes_ecb_cts_enc(fp,fp2,pid,key);
		printf("\n \t AES ECB CTS 加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}		
	else  
	if ((atoi(argv[1])== 0) && (atoi(argv[2]) == 1))
	{
		file_aes_hecb_dec(fp,fp2,pid,key); 
		printf("\n \t  AES ECB head clear 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 1) && (atoi(argv[2]) == 1))
	{
		file_aes_tecb_dec(fp,fp2,pid,key); 
		printf("\n \t  AES ECB trail clear 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 2) && (atoi(argv[2]) == 1))
	{
		file_aes_hcbc_Marlin_dec(fp,fp2,pid,key,iv); 
		printf("\n \t  AES CBC head clear for Marlin 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 3) && (atoi(argv[2]) == 1))
	{
		file_aes_tcbc_Marlin_dec(fp,fp2,pid,key,iv); 
		printf("\n \t  AES CBC trail clear for Marlin 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 4) && (atoi(argv[2]) == 1))
	{
		file_aes_cbc_cts_mdi_dec(fp,fp2,pid,key); 
		printf("\n \t  AES CBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 5) && (atoi(argv[2]) == 1))
	{
		file_aes_cbc_cts_mdd_dec(fp,fp2,pid,key); 
		printf("\n \t  AES CBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 6) && (atoi(argv[2]) == 1))
	{
		file_aes_rcbc_cts_mdi_dec(fp,fp2,pid,key); 
		printf("\n \t  AES RCBC CTS MDI for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 7) && (atoi(argv[2]) == 1))
	{
		file_aes_rcbc_cts_mdd_dec(fp,fp2,pid,key); 
		printf("\n \t  AES RCBC CTS MDD for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 8) && (atoi(argv[2]) == 1))
	{
		file_aes_cbc_cts_all_dec(fp,fp2,key); 
		printf("\n \t  AES CBC CTS ALL for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 9) && (atoi(argv[2]) == 1))
	{
		file_aes_rcbc_cts_all_dec(fp,fp2,key); 
		printf("\n \t  AES RCBC CTS ALL for ETSI 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else  
	if ((atoi(argv[1])== 10) && (atoi(argv[2]) == 1))
	{
		file_aes_dvs042_dec(fp,fp2,pid,key,iv); 
		printf("\n \t  AES DVS042 for Marlin 解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}	
	else  
	if ((atoi(argv[1])== 11) && (atoi(argv[2]) == 1))
	{
		file_aes_ecb_cts_dec(fp,fp2,pid,key); 
		printf("\n \t AES ECB CTS 解扰完毕,明文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}		
	else
		printf("请选择是AES加解扰模式配置\n"); 
		return FAIL;
}

void aes_print_help()
{
int i ;
printf("\n");
for( i = 0 ; i < 39 ; i++)
{
printf("\t%s\n",AES_USE_HELP[i]);
}
return ;
}

int file_aes_hecb_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	
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
				N = (188 - offset) / 16; 	
				offset += (188 - offset) % 16;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 16;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, cws, 16);
					CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
					for(k=offset;k<offset + 16;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 16;
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


int file_aes_tecb_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 16;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, cws, 16);
					CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
					for(k=offset;k<offset + 16;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 16;
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

int file_aes_hcbc_Marlin_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		for(j=0;j<16;j++)
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
				N = (188 - offset) / 16; 	
				offset += (188 - offset) % 16;
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 16;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_decrypt(c, pt,16);
					for(k=offset;k<offset + 16;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 16;
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

int file_aes_tcbc_Marlin_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		for(j=0;j<16;j++)
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
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<N;j++)
					{
					for(k=offset;k<offset + 16;k++)
						{
						pt[k-offset] = buf[k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_decrypt(c, pt,16);
					for(k=offset;k<offset + 16;k++)
						{
						buf_o[k] = pt[k-offset] ;										
						}
					offset += 16;
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

int file_aes_cbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
				
				ive[15] = offset;										
				CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_encrypt(c, ive, 16);				
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
									for(k=offset;k<offset + 16;k++)
										{
										pt[k-offset] = buf[k] ;														
										}
									CRYPTO_API_aes128_init(&aes128);
									c = &(aes128.c);
									c->set_key(c, cws, 16);
									c->buf = ive;
									CRYPTO_API_aes_cbc_cts_decrypt(c, pt, 16);								
									for(k=offset;k<offset + 16;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 16;
								}
								for(j=0;j<16;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 16;
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
								if(N >= 2)
									{
										for(j=0;j<16;j++)
										{
										buf_o[188-trail-16+j]= pt[j]^buf[188-trail-32+j];
										}
									}
								else
									{
										for(j=0;j<16;j++)
										{
										buf_o[188-trail-16+j]= pt[j]^ive[j];
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
							for(k=offset;k<offset + 16;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, cws, 16);
							c->buf = ive;
							CRYPTO_API_aes_cbc_cts_decrypt(c, pt, 16);								
							for(k=offset;k<offset + 16;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 16;
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

int file_aes_cbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
				
				ive[15] = offset;
				if(offset % 16)						
					ive_offset = offset/16 + 1;
				else
					ive_offset = offset/16;					
				ive_offset = ive_offset * 16;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/16);j++)
					{
					for(k=0;k<16;k++)										/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*16 + k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);						
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
					}	
					
				for(j=0;j<16;j++)		
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
									for(k=offset;k<offset + 16;k++)
										{
										pt[k-offset] = buf[k] ;														
										}
									CRYPTO_API_aes128_init(&aes128);
									c->set_key(c, cws, 16);
									c->buf = ive;
									CRYPTO_API_aes_cbc_cts_decrypt(c, pt, 16);								
									for(k=offset;k<offset + 16;k++)
										{
										buf_o[k] = pt[k-offset] ;										
										}
									offset += 16;
								}
								for(j=0;j<16;j++)							/* process Pn result */
									{
									pt[j] = buf[offset+j] ;	
									}
								offset += 16;
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);								
								for(j=0;j<trail;j++)
									{
									buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j];
									}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
								if(N >= 2)
									{
										for(j=0;j<16;j++)
										{
										buf_o[188-trail-16+j]= pt[j]^buf[188-trail-32+j];
										}
									}
								else
									{
										for(j=0;j<16;j++)
										{
										buf_o[188-trail-16+j]= pt[j]^ive[j];
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
							for(k=offset;k<offset + 16;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_aes128_init(&aes128);
							c->set_key(c, cws, 16);
							c->buf = ive;
							CRYPTO_API_aes_cbc_cts_decrypt(c, pt, 16);								
							for(k=offset;k<offset + 16;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 16;
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


int file_aes_rcbc_cts_mdi_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
//	unsigned char ive[16];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																	
				CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_encrypt(c, ive, 16);	
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
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+16+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 16;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 16;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<16;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-16-trail+j];
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
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
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j]^ive[j];
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
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+16+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 16;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 16;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<16;j++)													/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
										for(j=0;j<16;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 16;
										for(j=0;j<16;j++)													/* process last N-1 block */
										{
											pt[j] = buf[188-16-trail+j];
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
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
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j]^ive[j];
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
								for(j=0;j<16;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
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
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+16+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 16;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 16;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<16;j++)													/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 16;
								
								for(j=0;j<16;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+16+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 16;
								
								for(j=0;j<16;j++)													/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
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
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+16+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 16;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 16;	
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

int file_aes_rcbc_cts_mdd_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
//	unsigned char ive[16];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
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
				if(offset % 16)						
					ive_offset = offset/16 + 1;
				else
					ive_offset = offset/16;					
				ive_offset = ive_offset * 16;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/16);j++)
					{
					for(k=0;k<16;k++)											/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*16 + k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);						
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
					}
					
				for(j=0;j<16;j++)		
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
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+16+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 16;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 16;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}
										
										for(j=0;j<16;j++)											/* process last N-1 block */
										{
											pt[j] = buf[188-16-trail+j];
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
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
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j]^ive[j];
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
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^buf[offset+16+j];	
														ive[j]= ive[j]^buf_o[offset+j];		
													}
		//											hexprint(buf_o,188);
													offset += 16;	
													round++;
													round_flag = !round_flag;				
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[offset+j];	
													}
													
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[offset+j] = pt[j]^ive[j];
														ive[j]= ive[j]^buf_o[offset+j];		
													}
													offset += 16;	
													round++;
													round_flag = !round_flag;
		//											hexprint(buf_o,188);
												}									
										}																
										for(j=0;j<16;j++)												/* process last N-2 Block  */
										{
											pt[j] = buf[offset+j];	
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
										for(j=0;j<16;j++)
										{
											buf_o[offset+j] = pt[j]^ive[j] ;
											ive[j]= ive[j]^buf_o[offset+j];				
										}
										offset += 16;
										for(j=0;j<16;j++)												/* process last N-1 block */
										{
											pt[j] = buf[188-16-trail+j];
										}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
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
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j]^ive[j];
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
								for(j=0;j<16;j++)
								{
									pt[j] = buf[offset+j] ;		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
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
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+16+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 16;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 16;	
											round++;
											round_flag = !round_flag;
//											hexprint(buf_o,188);
										}									
								}																
								for(j=0;j<16;j++)														/* process last N-2 Block  */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j]^ive[j] ;
									ive[j]= ive[j]^buf_o[offset+j];				
								}
								offset += 16;
								
								for(j=0;j<16;j++)														/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j]^buf[offset+16+j] ;
									ive[j]= ive[j]^buf_o[offset+j];			
								}
								offset += 16;
								
								for(j=0;j<16;j++)														/* process last N Block (N>=3) */
								{
									pt[j] = buf[offset+j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
								for(j=0;j<16;j++)
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
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^buf[offset+16+j];	
												ive[j]= ive[j]^buf_o[offset+j];		
											}
//											hexprint(buf_o,188);
											offset += 16;	
											round++;
											round_flag = !round_flag;				
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[offset+j];	
											}
											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[offset+j] = pt[j]^ive[j];
												ive[j]= ive[j]^buf_o[offset+j];		
											}
											offset += 16;	
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

int file_aes_cbc_cts_all_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
				
		CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
		c = &(aes128.c);
		c->set_key(c, cws, 16);
		CRYPTO_API_aes_ecb_encrypt(c, ive, 16);		
		
		//packet cfg
		offset = 0;
		N = (188 - offset) / 16;
		trail = (188 - offset) % 16;												
		{
			for(j=0;j<N-1;j++)							/* N -1 block process */
			{
				for(k=offset;k<offset + 16;k++)
					{
					pt[k-offset] = buf[k] ;														
					}
				CRYPTO_API_aes128_init(&aes128);
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				c->buf = ive;
				CRYPTO_API_aes_cbc_cts_decrypt(c, pt, 16);								
				for(k=offset;k<offset + 16;k++)
					{
					buf_o[k] = pt[k-offset] ;										
					}
				offset += 16;
			}
			for(j=0;j<16;j++)							/* process Pn result */
				{
				pt[j] = buf[offset+j] ;	
				}
			offset += 16;
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_decrypt(c, pt, 16);								
			for(j=0;j<trail;j++)
				{
				buf_o[188-trail+j]= pt[j]^buf[188-trail+j];
				}
			for(j=0;j<trail;j++)						/* process Pn-1 result */
				{
				pt[j]=buf[offset+j];
				}
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
			if(N >= 2)
				{
					for(j=0;j<16;j++)
					{
					buf_o[188-trail-16+j]= pt[j]^buf[188-trail-32+j];
					}
				}
			else
				{
					for(j=0;j<16;j++)
					{
					buf_o[188-trail-16+j]= pt[j]^ive[j];
					}
				}
											
		}						
		for (j=0;j<188;j++)
			{
			fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
			}						
		}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_aes_rcbc_cts_all_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};	
		CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
		c = &(aes128.c);
		c->set_key(c, cws, 16);
		CRYPTO_API_aes_ecb_encrypt(c, ive, 16);		
			
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}		
		{			
			//packet cfg
			round = 0;
			round_flag=1;
			offset = 0;
			trail = 0;
			N = (188 - offset) / 16;
			trail = (188 - offset) % 16;				
																			
			//start dec packet								
			{
				N= N+1;										
				while(round < N-2)
				{
					if(round_flag)
						{
							for(j=0;j<16;j++)
							{
								pt[j] = buf[offset+j];	
							}									
							CRYPTO_API_aes128_init(&aes128);							
							c = &(aes128.c);
							c->set_key(c, cws, 16);
							CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
							for(j=0;j<16;j++)
							{
								buf_o[offset+j] = pt[j]^buf[offset+16+j];	
								ive[j]= ive[j]^buf_o[offset+j];		
							}
							offset += 16;	
							round++;
							round_flag = !round_flag;				
						}
					else
						{
							for(j=0;j<16;j++)
							{
								pt[j] = buf[offset+j];	
							}
							
							CRYPTO_API_aes128_init(&aes128);							
							c = &(aes128.c);
							c->set_key(c, cws, 16);
							CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
							for(j=0;j<16;j++)
							{
								buf_o[offset+j] = pt[j]^ive[j];
								ive[j]= ive[j]^buf_o[offset+j];		
							}
							offset += 16;	
							round++;
							round_flag = !round_flag;
						}									
				}
				
				for(j=0;j<16;j++)											/* process last N-1 block */
				{
					pt[j] = buf[188-16-trail+j];
				}
				CRYPTO_API_aes128_init(&aes128);							
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_decrypt(c, pt, 16);	
				for(j=0;j<trail;j++)
				{
					buf_o[188-trail+j] = pt[j]^buf[188-trail+j];
					ive[j]= ive[j]^buf_o[188-trail+j];
				}
				for(j=0;j<trail;j++)										/* process trail block */
					{
						pt[j] = buf[188-trail+j];
					}
				CRYPTO_API_aes128_init(&aes128);							
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
				for(j=0;j<16;j++)
				{
					buf_o[188-16-trail+j] = pt[j]^ive[j];
				}										
			}																														
			for (j=0;j<188;j++)
			{
			fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
			}				
		}					
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_aes_hecb_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];

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
				if((buf[1]&0x40) == 0x40)													  //pusi flag
					buf[3] = buf[3];
				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				if((buf[1]&0x40) == 0x40)													/* pusi flag packet */
				{
					for (j=0;j<188;j++)								
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
					}
				}
				else
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
					N = (188 - offset) / 16; 					
					offset += (188 - offset) % 16;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+16;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_aes128_init(&aes128);
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
						for(k=offset;k<offset+16;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 16;
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

int file_aes_tecb_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];

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
				if((buf[1]&0x40) == 0x40)													  //pusi flag
					buf[3] = buf[3];
				else
					buf[3] = buf[3] | 0x80;													  /* add scrambling bits */	
				
				for (j=0;j<188;j++)								
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				if((buf[1]&0x40) == 0x40)
				{
					for (j=0;j<188;j++)								
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
					}
				}
				else
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
					N = (188 - offset) / 16;
					trail = (188 - offset) % 16;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+16;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_aes128_init(&aes128);
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
						for(k=offset;k<offset+16;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 16;
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

int file_aes_hcbc_Marlin_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char cws[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];

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
		for(j=0;j<16;j++)
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
					N = (188 - offset) / 16; 					
					offset += (188 - offset) % 16;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+16;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_aes128_init(&aes128);
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						c->buf = ive;
						CRYPTO_API_aes_cbc_encrypt(c, pt, 16);
						for(k=offset;k<offset+16;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 16;
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

int file_aes_tcbc_Marlin_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char cws[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];

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
		for(j=0;j<16;j++)
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
					N = (188 - offset) / 16;
					trail = (188 - offset) % 16;
					for(j=0;j<offset;j++)
						{
						buf_o[j] = buf[j] ;
						}
					for(j=0;j<N;j++)
					{
						for(k=offset;k<offset+16;k++)
							{
							pt[k-offset] = buf[k] ;														
							}
						CRYPTO_API_aes128_init(&aes128);
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						c->buf = ive;
						CRYPTO_API_aes_cbc_encrypt(c, pt, 16);
						for(k=offset;k<offset+16;k++)
							{
							buf_o[k] = pt[k-offset] ;										
							}
						offset += 16;
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

int file_aes_cbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
		
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
				
				ive[15] = offset;														
				CRYPTO_API_aes128_init(&aes128);										/* calculate IVE	*/
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_encrypt(c, ive, 16);			
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
									for(k=offset;k<offset + 16;k++)
										{
										pt[k-offset] = buf[k] ;														
										}
									CRYPTO_API_aes128_init(&aes128);
									c = &(aes128.c);
									c->set_key(c, cws, 16);
									c->buf = ive;
									CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
									for(k=0;k<16;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 16;
								}												
								if(N >= 2)
									{
									for(j=0;j<16;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-16+j] ;	
										}
									offset += 16;	
									}
								else
									{
									for(j=0;j<16;j++)									/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 16;		
									}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);								
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)									/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}							
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
								for(j=0;j<16;j++)
									{
									buf_o[offset-16+j]= pt[j];
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
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, cws, 16);
							c->buf = ive;
							CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);								
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

int file_aes_cbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
		
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
				
				ive[15] = offset;														
				if(offset % 16)						
					ive_offset = offset/16 + 1;
				else
					ive_offset = offset/16;					
				ive_offset = ive_offset * 16;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/16);j++)
					{
					for(k=0;k<16;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*16 + k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);						
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
					}	
					
				for(j=0;j<16;j++)		
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
									for(k=offset;k<offset + 16;k++)
										{
										pt[k-offset] = buf[k] ;														
										}
									CRYPTO_API_aes128_init(&aes128);
									c = &(aes128.c);
									c->set_key(c, cws, 16);
									c->buf = ive;
									CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
									for(k=0;k<16;k++)
										{
										buf_o[offset+k] = pt[k] ;										
										}
									offset += 16;
								}												
								if(N >= 2)
									{
									for(j=0;j<16;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^buf_o[offset-16+j] ;	
										}
									offset += 16;	
									}
								else
									{
									for(j=0;j<16;j++)							/* process Pn result */
										{
										pt[j] = buf[offset+j]^ive[j] ;	
										}
									offset += 16;		
									}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);								
								for(j=0;j<trail;j++)
									{
									buf_o[offset+j]= pt[j];
									}
								for(j=0;j<trail;j++)						/* process Pn-1 result */
									{
									pt[j]=buf[offset+j]^pt[j];
									}							
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
								for(j=0;j<16;j++)
									{
									buf_o[offset-16+j]= pt[j];
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
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, cws, 16);
							c->buf = ive;
							CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);								
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

int file_aes_rcbc_cts_mdi_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive_tmp[16];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																	
				CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				CRYPTO_API_aes_ecb_encrypt(c, ive, 16);	
//				hexprint(ive,16);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<16;j++)											/* IVE initial */
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<16;j++)											
											{
												pt[j] = buf[188-16-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<16;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
														}
													}
													for(j=0;j<16;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+2)*16+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[188-trail-(round+2)*16+j]^pt[j];	
													}											
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+2)*16+j] = pt[j];
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}												
										for(j=0;j<16;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<16;j++)
											{
												buf_o[188-32-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<16;j++)											
											{
												pt[j] = buf[188-16-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<16;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
														}
													}
													for(j=0;j<16;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+3)*16+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[188-trail-(round+3)*16+j]^pt[j];	
													}											
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+3)*16+j] = pt[j];
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
								for(j=0;j<16;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<16;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
									}
								}
								for(j=0;j<16;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<16;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(32-j)]^pt[j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(32-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<16;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
									}
								}
								for(j=0;j<16;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(48-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}
											for(j=0;j<16;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+4)*16+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[188-(round+4)*16+j]^pt[j];	
											}											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+4)*16+j] = pt[j];
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}
											for(j=0;j<16;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+1)*16+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[188-(round+1)*16+j]^pt[j];	
											}											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+1)*16+j] = pt[j];
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

int file_aes_rcbc_cts_mdd_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char pid[0x2],unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	unsigned char ive_buf[189];
	unsigned int ive_offset;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive_tmp[16];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};			
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;				
//				printf("packet_num = %d,  N = %d,  offset = %d,  trail = %d \n",i,N,offset,trail);
																	
				if(offset % 16)						
					ive_offset = offset/16 + 1;
				else
					ive_offset = offset/16;					
				ive_offset = ive_offset * 16;
				
				for(j=0;j<offset;j++)
					{
					ive_buf[j] = buf[j];
					}
				ive_buf[1]= ive_buf[1]& (0x7f);
					
				for(j=0;j<ive_offset -offset;j++) 
					{
					ive_buf[offset+j] = 0x0;
					}
				for(j=0;j<(ive_offset/16);j++)
					{
					for(k=0;k<16;k++)															/* calculate IVE	*/
						{
						pt[k] = ive_buf[j*16 + k] ;														
						}
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);						
					c->set_key(c, cws, 16);
					c->buf = ive;
					CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
					}	
					
				for(j=0;j<16;j++)		
					{
					ive[j]=	pt[j];
					}
				hexprint(ive,16);				
				//start enc packet		
				for(j=0;j<offset;j++)
					{
					buf_o[j] = buf[j] ;
					}
				for(j=0;j<16;j++)											/* IVE initial */
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<16;j++)											
											{
												pt[j] = buf[188-16-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < N-2)
										{									
											if(round_flag)
												{
													for(j=0;j<N-2-round;j++)
													{
														for(k=0;k<16;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
														}
													}
													for(j=0;j<16;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+2)*16+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
//													hexprint(buf_o,188);		
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[188-trail-(round+2)*16+j]^pt[j];	
													}											
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+2)*16+j] = pt[j];
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}												
										for(j=0;j<16;j++)											
											{
												pt[j] =ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<16;j++)
											{
												buf_o[188-32-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);
										
										for(j=0;j<N-2;j++)											/* process last N-1 block */
											{
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}										
										for(j=0;j<trail;j++)	
											{
												ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
											}		
										for(j=0;j<16;j++)											
											{
												pt[j] = buf[188-16-trail+j]^ive_tmp[j];
												ive_tmp[j]=ive[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
										for(j=0;j<trail;j++)
											{
												buf_o[188-trail+j] = pt[j];
											}
//										hexprint(buf_o,188);

										for(j=0;j<trail;j++)										/* process trail block */
											{
												pt[j] = buf[188-trail+j]^pt[j];
											}
										CRYPTO_API_aes128_init(&aes128);							
										c = &(aes128.c);
										c->set_key(c, cws, 16);
										CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
										for(j=0;j<16;j++)
										{
											buf_o[188-16-trail+j] = pt[j];
										}
//										hexprint(buf_o,188);		
																				
										while(round < (N-3))
										{									
											if(round_flag)
												{
													for(j=0;j<N-3-round;j++)
													{
														for(k=0;k<16;k++)
														{
															ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
														}
													}
													for(j=0;j<16;j++)
													{
														pt[j] = ive_tmp[j];	
														ive_tmp[j]=ive[j];
													}									
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+3)*16+j] = pt[j];
													}
													round++;
													round_flag = !round_flag;		
		//											hexprint(buf_o,188);
		//											printf("\nround = %d",round);		
												}
											else
												{
													for(j=0;j<16;j++)
													{
														pt[j] = buf[188-trail-(round+3)*16+j]^pt[j];	
													}											
													CRYPTO_API_aes128_init(&aes128);							
													c = &(aes128.c);
													c->set_key(c, cws, 16);
													CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
													for(j=0;j<16;j++)
													{
														buf_o[188-trail-(round+3)*16+j] = pt[j];
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
								for(j=0;j<16;j++)
								{
									pt[j] = buf[offset+j]^ive[j] ;		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[offset+j] = pt[j];		
								}
//								hexprint(buf_o,188);									
							}
						else if( (N%2)==1 )															/* N is odd and >=3 */
							{										
								for(j=0;j<N;j++)													/* process last N Block (N>=3) */
								{
									for(k=0;k<16;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
									}
								}
								for(j=0;j<16;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
											
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(16-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);

								for(j=0;j<16;j++)													/* process last N-1 Block (N>=3) */
								{
									pt[j] = buf[188-(32-j)]^pt[j];	
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(32-j)] = pt[j];		
								}
//								hexprint(buf_o,188);
							
								for(j=0;j<N-2;j++)													/* process last N-2 Block (N>=3) */
								{
									for(k=0;k<16;k++)
									{
										ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
									}
								}
								for(j=0;j<16;j++)													
								{
									pt[j] = ive_tmp[j];	
									ive_tmp[j]=ive[j];		
								}
								CRYPTO_API_aes128_init(&aes128);							
								c = &(aes128.c);
								c->set_key(c, cws, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
								for(j=0;j<16;j++)
								{
									buf_o[188-(48-j)] = pt[j];		
								}		
//								hexprint(buf_o,188);
								while(round < (N-3))
								{									
									if(round_flag)
										{
											for(j=0;j<N-3-round;j++)
											{
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}
											for(j=0;j<16;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+4)*16+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);
//											printf("\nround = %d",round);		
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[188-(round+4)*16+j]^pt[j];	
											}											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+4)*16+j] = pt[j];
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
												for(k=0;k<16;k++)
												{
													ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
												}
											}
											for(j=0;j<16;j++)
											{
												pt[j] = ive_tmp[j];	
												ive_tmp[j]=ive[j];
											}									
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+1)*16+j] = pt[j];
											}
											round++;
											round_flag = !round_flag;		
//											hexprint(buf_o,188);		
										}
									else
										{
											for(j=0;j<16;j++)
											{
												pt[j] = buf[188-(round+1)*16+j]^pt[j];	
											}											
											CRYPTO_API_aes128_init(&aes128);							
											c = &(aes128.c);
											c->set_key(c, cws, 16);
											CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
											for(j=0;j<16;j++)
											{
												buf_o[188-(round+1)*16+j] = pt[j];
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

int file_aes_cbc_cts_all_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive[16];
	
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
		
		for(j=0;j<16;j++)
		{
			ive[j] = 0x0;
		}
		ive[7] = 0xbc;
		CRYPTO_API_aes128_init(&aes128);										/* calculate IVE	*/
		c = &(aes128.c);
		c->set_key(c, cws, 16);
		CRYPTO_API_aes_ecb_encrypt(c, ive, 16);	
				
		//packet cfg
		offset = 0;
		N = (188 - offset) / 16;
		trail = (188 - offset) % 16;												
		{
			for(j=0;j<N-1;j++)										/* N -1 block process */
			{
				for(k=offset;k<offset + 16;k++)
					{
					pt[k-offset] = buf[k] ;														
					}
				CRYPTO_API_aes128_init(&aes128);
				c = &(aes128.c);
				c->set_key(c, cws, 16);
				c->buf = ive;
				CRYPTO_API_aes_cbc_cts_encrypt(c, pt, 16);							
				for(k=0;k<16;k++)
					{
					buf_o[offset+k] = pt[k] ;										
					}
				offset += 16;
			}												
			if(N >= 2)
				{
				for(j=0;j<16;j++)									/* process Pn result */
					{
					pt[j] = buf[offset+j]^buf_o[offset-16+j] ;	
					}
				offset += 16;	
				}
			else
				{
				for(j=0;j<16;j++)									/* process Pn result */
					{
					pt[j] = buf[offset+j]^ive[j] ;	
					}
				offset += 16;		
				}
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_encrypt(c, pt, 16);								
			for(j=0;j<trail;j++)
				{
				buf_o[offset+j]= pt[j];
				}
			for(j=0;j<trail;j++)									/* process Pn-1 result */
				{
				pt[j]=buf[offset+j]^pt[j];
				}							
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
			for(j=0;j<16;j++)
				{
				buf_o[offset-16+j]= pt[j];
				}																
		}					
		for (j=0;j<188;j++)
		{
			fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
		}												
	}
	fclose ( file_encrypted );
	fclose ( file_decrypted );
	return SUCCESS;
}

int file_aes_rcbc_cts_all_enc(FILE *file_decrypted,FILE *file_encrypted,unsigned char cws[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k,round,round_flag=1;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	unsigned char ive_tmp[16];
		
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);

	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	
	for ( i=0;i<packet_num;i++)
	{
		unsigned char ive[16] = {0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd,0xcb,0xce,0xcb,0xcd};	
		
		CRYPTO_API_aes128_init(&aes128);							/* calculate IVE	*/
		c = &(aes128.c);
		c->set_key(c, cws, 16);
		CRYPTO_API_aes_ecb_encrypt(c, ive, 16);		
		
		for(j=0;j<16;j++)											/* IVE initial */
			{
				ive_tmp[j]=ive[j];
			}	
							
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}				
		//packet cfg
		round = 0;
		round_flag =1;
		offset = 0;			
		N = (188 - offset) / 16;
		trail = (188 - offset) % 16;																					
		//start enc packet								
		{
			N= N+1;										
			for(j=0;j<N-2;j++)											/* process last N-1 block */
				{
					for(k=0;k<16;k++)
					{
						ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
					}
				}										
			for(j=0;j<trail;j++)	
				{
					ive_tmp[j]= ive_tmp[j]^buf[188-trail+j];
				}		
			for(j=0;j<16;j++)											
				{
					pt[j] = buf[188-16-trail+j]^ive_tmp[j];
					ive_tmp[j]=ive[j];
				}
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
			for(j=0;j<trail;j++)
				{
					buf_o[188-trail+j] = pt[j];
				}

			for(j=0;j<trail;j++)										/* process trail block */
				{
					pt[j] = buf[188-trail+j]^pt[j];
				}
			CRYPTO_API_aes128_init(&aes128);							
			c = &(aes128.c);
			c->set_key(c, cws, 16);
			CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
			for(j=0;j<16;j++)
			{
				buf_o[188-16-trail+j] = pt[j];
			}	
													
			while(round < N-2)
			{									
				if(round_flag)
					{
						for(j=0;j<N-2-round;j++)
						{
							for(k=0;k<16;k++)
							{
								ive_tmp[k]= ive_tmp[k]^buf[offset+j*16+k];		
							}
						}
						for(j=0;j<16;j++)
						{
							pt[j] = ive_tmp[j];	
							ive_tmp[j]=ive[j];
						}									
						CRYPTO_API_aes128_init(&aes128);							
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
						for(j=0;j<16;j++)
						{
							buf_o[188-trail-(round+2)*16+j] = pt[j];
						}
						round++;
						round_flag = !round_flag;			
					}
				else
					{
						for(j=0;j<16;j++)
						{
							pt[j] = buf[188-trail-(round+2)*16+j]^pt[j];	
						}											
						CRYPTO_API_aes128_init(&aes128);							
						c = &(aes128.c);
						c->set_key(c, cws, 16);
						CRYPTO_API_aes_ecb_encrypt(c, pt, 16);	
						for(j=0;j<16;j++)
						{
							buf_o[188-trail-(round+2)*16+j] = pt[j];
						}
						round++;
						round_flag = !round_flag;
					}									
			}										
		}																					
		for (j=0;j<188;j++)
		{
		fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
		}
	}				
	fclose ( file_decrypted );
	fclose ( file_encrypted );
	return SUCCESS;

}

int file_aes_dvs042_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j;
	unsigned int offset=4;
	unsigned int payload_length=184;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
		
	unsigned char pt[184];
	unsigned char iv_tmp[16];
	
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
		
		for (j=0;j<16;j++)
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
				if(payload_length >= 16)													/* packet payload  >= whole  block */
					{
								
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, key, 16);
					c->buf = iv_tmp;
					CRYPTO_API_aes_cbc_dvs042_encrypt(c, pt, payload_length);			
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset] ;										
						}			
					}
				else																	/* packet payload < whole  block */
					{
						CRYPTO_API_aes128_init(&aes128);
						c = &(aes128.c);
						c->set_key(c, key, 16);
						c->buf = iv_tmp;
						CRYPTO_API_aes_ecb_encrypt(c, iv_tmp, 16);	
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

int file_aes_ecb_cts_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],unsigned char key[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];

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
					N = (188 - offset) / 16;
					trail = (188 - offset) % 16;
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
								for(k=offset;k<offset+16;k++)
									{
									pt[k-offset] = buf[k] ;														
									}
								CRYPTO_API_aes128_init(&aes128);
								c = &(aes128.c);
								c->set_key(c, key, 16);
								CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
																							
								for(k=offset;k<offset+16;k++)
									{
									buf_o[k] = pt[k-offset];										
									}
								offset += 16;			
								}
								
							for(j =0; j< 16;j++)										/* process the last N */	
								{
									pt[j] = buf[172+j];
								}
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, key, 16);
							CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
							for(j=0;j<16;j++)
								{
								buf_o[172+j] = pt[j];										
								}						
		
							for(j =0; j< trail;j++ )							 		/* split last N process */
								{
								pt[j] = buf[172-trail+j];														
								}
							for(j =0; j< (16-trail);j++ )
								{
								pt[trail+j] = buf_o[172+j];
								}
							CRYPTO_API_aes128_init(&aes128);                   		/* last split process */
							c = &(aes128.c);       
							c->set_key(c, key, 16);
							CRYPTO_API_aes_ecb_encrypt(c, pt, 16);							
							for(j=0;j<16;j++)
								{
								buf_o[172-trail+j] = pt[j];										
								}					
						}
						else															/* only payload < 16 */
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
							for(k=offset;k<offset+16;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, key, 16);
							CRYPTO_API_aes_ecb_encrypt(c, pt, 16);
							for(k=offset;k<offset+16;k++)
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

int file_aes_dvs042_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key[0x10],unsigned char iv[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j;
	unsigned int offset=4;
	unsigned int payload_length=184;
	
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
		
	unsigned char pt[184];
	unsigned char iv_tmp[16];
	
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
		for (j=0;j<16;j++)												//initial iv data every packet
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
				
				if(payload_length >= 16)													/* packet payload  >= whole  block */
					{
					
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, key, 16);		
					c->buf = iv_tmp;
					CRYPTO_API_aes_cbc_dvs042_decrypt(c, pt, payload_length);				
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset] ;										
						}			
					}
				else																	/* packet payload < whole  block  ?? */
					{
					CRYPTO_API_aes128_init(&aes128);
					c = &(aes128.c);
					c->set_key(c, key, 16);
					hexprint(key,16);
					printf("\n key  = %d");
					c->buf = iv_tmp;					
					hexprint(iv_tmp,16);
					printf("\n iv  = %d");
					CRYPTO_API_aes_ecb_encrypt(c, iv_tmp, 16);
					hexprint(iv_tmp,16);
					printf("\n dec  = %d");
					hexprint(pt,188-offset);	
					printf("\n pt  = %d");
					for(j=offset;j<188;j++)
						{
						buf_o[j] = pt[j-offset]^iv_tmp[j-offset] ;										
						}
					hexprint(buf_o,188);	
					printf("\n result  = %d",length);
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

int file_aes_ecb_cts_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],unsigned char key[0x10])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j,k;
	unsigned int offset=4,N,trail;
	
	CRYPTO_AES128_CONTEX aes128;
	PCRYPTO_BLOCK_CIPHER c = 0; 
	unsigned char pt[16];
	
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
				N = (188 - offset) / 16;
				trail = (188 - offset) % 16;
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
								for(k=offset;k<offset+16;k++)
									{
									pt[k-offset] = buf[k] ;														
									}
								CRYPTO_API_aes128_init(&aes128);
								c = &(aes128.c);
								c->set_key(c, key, 16);
								CRYPTO_API_aes_ecb_decrypt(c, pt, 16);					
								for(k=offset;k<offset+16;k++)
									{
									buf_o[k] = pt[k-offset];										
									}
								offset += 16;			
								}
																						/* process last N */		
							for(j =0; j< (16-trail);j++ )
								{
								pt[j] = buf_o[offset-16+trail+j];														
								}
							for(j =0; j< trail;j++ )
								{
								pt[16-trail+j] = buf[offset+j];
								}
							CRYPTO_API_aes128_init(&aes128);           					/* last split process */
							c = &(aes128.c);       
							c->set_key(c, key, 16);
							CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
							for(j=16;j>0;j--)
								{
								buf_o[188-j] = pt[16-j];										
								}						
						}
						else															/* only payload < 16 */
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
							for(k=offset;k<offset+16;k++)
								{
								pt[k-offset] = buf[k] ;														
								}
							CRYPTO_API_aes128_init(&aes128);
							c = &(aes128.c);
							c->set_key(c, key, 16);
							CRYPTO_API_aes_ecb_decrypt(c, pt, 16);
							for(k=offset;k<offset+16;k++)
								{
								buf_o[k] = pt[k-offset] ;										
								}
							offset += 16;	
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