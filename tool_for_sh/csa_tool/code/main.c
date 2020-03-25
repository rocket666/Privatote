/*********************************************************************/
/*-文件名：CSA.c */
/*-版本号：v 0.0.2*/
/*-功能： 实现CSA算法的加扰解扰功能*/
/*- add pes 层加解扰功能*/
/*- */
/*********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "csa.h"
#define SUCCESS 0 
#define FAIL -1

char  *CSA_USE_HELP[]={
"输入14个参数:",
"\t 1.可执行文件名 *.exe",
"\t 2.TS或PES 层加解扰 0：ts 层； 1：pes层;",
"\t 3.操作类型 1:加扰;2:解扰;",
"\t 4.读出数据的文件名*.ts",
"\t 5.写入数据的文件名*.ts", 
"\t 6.PID号,16进制表示",  
"\t 7.密钥第1个字节", 
"\t 8.密钥第2个字节", 
"\t 9.密钥第3个字节", 
"\t 10.密钥第4个字节", 
"\t11.密钥第5个字节", 
"\t12.密钥第6个字节", 
"\t13.密钥第7个字节", 
"\t14.密钥第8个字节", 
"\t例:csa 0 1 1.ts 2.ts 0x203 0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06",
"\t注意：PID号为13位数据必须为16进制表示,如 0x01ff，0x1010",
"\t所有输入的密钥数据必须为16进制表示,如 0x01 0xff",
"\t ******************************************************"
};

void csa_print_help();
int file_ts_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],
unsigned char key[0x8]);
int file_pes_enc(FILE *readfile,FILE *writefile,unsigned char pid[0x2],
unsigned char key[0x8]);
int file_ts_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],
unsigned char key[0x8]);
int file_pes_dec(FILE *readfile,FILE *writefile,unsigned char pid[0x2],
unsigned char key[0x8]);

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
unsigned char key_tmp[8][4];
unsigned char key[0x8];

int i,j;

if ( argc == 14 && (atoi(argv[1]) == 0 || atoi(argv[1]) == 1 ) &&(atoi(argv[2]) == 1 || atoi(argv[2]) == 2 ))
{
}
else
{
csa_print_help();
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
		pid[0] = char2int('0', '0');		
		pid[1] = char2int(pid_tmp[1][1], pid_tmp[1][0]);
	}
}
else if (strlen(argv[5]) == 3)
{
	pid_tmp[0][2] = argv[5][2];
	pid_tmp[1][0] = argv[5][2];
	pid[0] = char2int('0', '0');		
	pid[1] = char2int(pid_tmp[1][0], '0');
}


for(i = 0; i < 8; i++)
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

printf("\npid  = %02x %02x",pid[0],pid[1]);
printf("\ncw   = %02x %02x %02x %02x %02x %02x %02x %02x\n",key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7]);

if ((fp= fopen(FILENAME1,"rb")) == NULL || (fp2 = fopen(FILENAME2,"wb"))==NULL)
{ 

printf("Can't open file\n");
return FAIL;
}    

	if((atoi(argv[1])== 0) && (atoi(argv[2]) == 1))
	{
		file_ts_enc(fp,fp2,pid,key);
		printf("\n \tCSA ts层加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else if ((atoi(argv[1])== 0) && (atoi(argv[2]) == 2))
	{
		file_ts_dec(fp,fp2,pid,key); 
		printf("\n \tCSA ts层解扰完毕,明文存于%s文件\n",FILENAME2);	
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else if ((atoi(argv[1])== 1) && (atoi(argv[2]) == 1))
	{
		file_pes_enc(fp,fp2,pid,key);
		printf("\n \tCSA pes层加扰完毕,密文存于%s文件\n",FILENAME2); 
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else if ((atoi(argv[1])== 1) && (atoi(argv[2]) == 2))
	{
		file_pes_dec(fp,fp2,pid,key); 
		printf("\n \tCSA pes层解扰完毕,明文存于%s文件\n",FILENAME2);
		fclose(fp);
		fclose(fp2);
		return SUCCESS;
	}
	else
		printf("请选择是ts层加扰01│ts层解扰02|pes层加扰11|pes层解扰12\n"); 
}


void csa_print_help()
{
int i ;
printf("\n");
for( i = 0 ; i < 19 ; i++)
{
printf("\t%s\n",CSA_USE_HELP[i]);
}
return ;
}

int file_ts_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],
unsigned char cws[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i;
	unsigned int j;
	struct key key;
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	set_cws(cws, &key);

	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x20)==0x20) && ((buf[3]& 0x10)!= 0x10) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\nno payload packet   ");
				printf("packet_num = %d\n",i+1);
				buf[3] &= 0x3f; 									 		/* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
				}												
			}
			else if(((buf[3]&0x80)==0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				decrypt( 0,&key,buf,buf_o);
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

int file_pes_dec(FILE *file_encrypted,FILE *file_decrypted,unsigned char pid[0x2],
unsigned char cws[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned long int packet_num,length,i,field_length,pes_head_length_addr,pes_scrambling_staddr;
	unsigned int j, pes_start_flag;
	struct key key;
	
	fseek(file_encrypted , 0L, SEEK_END);
	length = ftell(file_encrypted);

	fseek(file_encrypted , 0L, SEEK_SET);
	packet_num=length/(188);

	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	set_cws(cws, &key);
	
	pes_start_flag = 0;
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_encrypted);   
		}
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x20)==0x20) && ((buf[3]& 0x10)!= 0x10) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\nno payload packet, pes dec error!!!!! ");
				printf(" packet_num = %d",i+1);
				buf[3] &= 0x3f; 										 /* remove scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);  
				}
			}
			else if(((buf[1]&0x40)==0x40)&& ((buf[3]&0x20)!=0x20) && ((buf[3]& 0x10)== 0x10)&& ((buf[10]&0x20)==0x20) && ( (buf[3]&0x80)!= 0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				if(buf[12]> 176)
					{
						printf("\npes descrambling error,pes_head_length > 184 !!! ");
						printf(" packet_num = %d",i+1);
						for (j=0;j<188;j++)
						{
							fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);  
						}
					}
				else
				{	pes_start_flag	= 1;
					decrypt(1,&key,buf,buf_o);
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_decrypted);
					}
				}
			}
			else if(((buf[1]&0x40)==0x40)&& ((buf[3]& 0x30)== 0x30)&& ( (buf[3]&0x80)!= 0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				field_length = buf[4];
				pes_head_length_addr  = field_length + 13;
				pes_scrambling_staddr = field_length + 11;
				
				if (field_length > 174)
				{
					printf("\npes descrambling error,pes_head_field_length > 174!!!");
					printf(" packet_num = %d",i+1);
					for (j=0;j<188;j++)
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
					}
				}
				else if ((buf[pes_head_length_addr]+ pes_head_length_addr)> 188)
				{
					printf("\npes descrambling error,pes_head_length + field_lenth > 188!!!");
					printf(" packet_num = %d",i+1);
					for (j=0;j<188;j++)
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_decrypted);
					}
				}
				else if  ((buf[pes_scrambling_staddr]&0x20)==0x20) 
				{	pes_start_flag	= 1;
					decrypt(1,&key,buf,buf_o);
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
			else if(pes_start_flag && (((buf[3]&0x80)!= 0x80)&& (buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
//			else if(pes_start_flag && (((buf[3]&0x80)== 0x80)&& (buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				decrypt(1,&key,buf,buf_o);
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

int file_ts_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],
unsigned char cws[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i,j;
	struct key key;
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	set_cws(cws, &key);
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x20)==0x20) && ((buf[3]& 0x10)!= 0x10) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\nno payload packet!!! ");
				printf("packet_num = %d",i+1);
				buf[3] = buf[3] | 0x80;						 /* add scrambling bits */
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				encrypt(0,&key,buf,buf_o);
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

int file_pes_enc(FILE *file_decrypted,FILE *file_encrypted , unsigned char pid[0x2],
unsigned char cws[0x8])
{
	unsigned char buf[189],buf_o[189];
	unsigned int packet_num,length,i,j,pes_start_flag,field_length,pes_head_length_addr,pes_scrambling_staddr;
	struct key key;
	
	fseek(file_decrypted , 0L, SEEK_END);
	length = ftell(file_decrypted);
	fseek(file_decrypted , 0L, SEEK_SET);
	packet_num=length/(188);
	printf("\npacket_num = %d",packet_num);
	printf("\nlength = %d",length);
	set_cws(cws, &key);
	pes_start_flag = 0;
	
	for ( i=0;i<packet_num;i++)
	{
		for (j=0;j<188;j++)
		{
			fread(&buf[j],sizeof(unsigned char),1,file_decrypted);
		}
		
		if(buf[0]==0x47) 
		{
			if(((buf[3]&0x20)==0x20) && ((buf[3]& 0x10)!= 0x10) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) )   // no payload 
			{
				printf("\nno payload packet, pes enc error!!! ");
				printf("packet_num = %d",i+1);
				for (j=0;j<188;j++)
				{
					fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
				}
			}
			else if(((buf[1]&0x40)==0x40)&& ((buf[3]&0x20)!=0x20) && ((buf[3]& 0x10)== 0x10)&& ((buf[10]&0x20)!=0x20) && ( (buf[3]&0x80)!= 0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				if(buf[12]> 176)
					{
						printf("\npes scrambling error,pes_head_length > 184 !!!");
						printf("packet_num = %d",i+1);
						for (j=0;j<188;j++)
						{
							fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
						}
					}
				else
				{	pes_start_flag	= 1;
					encrypt(1,&key,buf,buf_o);
					for (j=0;j<188;j++)
					{
						fwrite(&buf_o[j],sizeof(unsigned char),1,file_encrypted);
					}
				}
			}
			else if(((buf[1]&0x40)==0x40)&& ((buf[3]& 0x30)== 0x30)&& ( (buf[3]&0x80)!= 0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]) ) 
			{
				field_length = buf[4];
				pes_head_length_addr  = field_length + 13;
				pes_scrambling_staddr = field_length + 11;
				if (field_length > 174)
				{
					printf("\npes scrambling error,pes_head_field_length > 174!!! ");
					printf("packet_num = %d",i+1);
					for (j=0;j<188;j++)
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
					}
				}
				else if ((buf[pes_head_length_addr]+ pes_head_length_addr)> 188)
				{
					printf("\npes scrambling error,pes_head_length + field_lenth >188!!! ");
					printf("packet_num = %d",i+1);
					for (j=0;j<188;j++)
					{
						fwrite(&buf[j],sizeof(unsigned char),1,file_encrypted);
					}
				}
				else if  ((buf[pes_scrambling_staddr]&0x20)!=0x20) 
				{	pes_start_flag	= 1;
					encrypt(1,&key,buf,buf_o);
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
			else if (pes_start_flag && ((buf[3]&0x80)!=0x80) && ((buf[1]& pid[0]) == pid[0]) && (buf[2]== pid[1]))
			{
				encrypt(1,&key,buf,buf_o);
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
