aes 10 1 MyRec.ts MyRec_clear10.ts  0x200 0x00 0x20 0x20 0x02 0x26 0x17 0x47 0x17 0x44 0x23 0x60 0xab 0xcd 0xef 0x20 0x20 0x98 0x76 0x54 0x32 0x1a 0x12 0x34 0x56 0x78 0x9b 0xab 0xc1 0x23 0x45 0x67 0x89
@rem // 注释如下
@rem 输入38个参数:
@rem 1.可执行文件名 *.exe
@rem 2.AES 模式 0：ecb head clear; 1：ecb trail clear; 2: cbc head clear for Marlin;3: cbc trail clear for Marlin; 4: cbc cts mdi; 5: cbc cts mdd; 6: rcbc cts mdi; 7: rcbc cts mdd;8:cbc cts all;9: rcbc cts all 10：cbc dvs042 for Marlin  11：ecb cts mode
@rem 3.操作类型 0:加扰;1:解扰;
@rem 4.读出数据的文件名*.ts
@rem 5.写入数据的文件名*.ts 
@rem 6.PID号,16进制表示  
@rem 7.密钥第1个字节 
@rem 8.密钥第2个字节
@rem 9.密钥第3个字节 
@rem 10.密钥第4个字节 
@rem 11.密钥第5个字节
@rem 12.密钥第6个字节 
@rem 13.密钥第7个字节 
@rem 14.密钥第8个字节
@rem 15.密钥第9个字节 
@rem 16.密钥第10个字节 
@rem 17.密钥第11个字节
@rem 18.密钥第12个字节 
@rem 19.密钥第13个字节
@rem 20.密钥第14个字节
@rem 21.密钥第15个字节 
@rem 22.密钥第16个字节 
@rem 23.IV第1个字节
@rem 24.IV第2个字节
@rem 25.IV第3个字节
@rem 26.IV第4个字节
@rem 27.IV第5个字节
@rem 28.IV第6个字节
@rem 29.IV第7个字节 
@rem 30.IV第8个字节 
@rem 31.IV第9个字节 
@rem 32.IV第10个字节 
@rem 33.IV第11个字节 
@rem 34.IV第12个字节
@rem 35.IV第13个字节 
@rem 36.IV第14个字节
@rem 37.IV第15个字节
@rem 38.IV第16个字节 
@rem 例:aes 0 1 1.ts 2.ts 0x203  0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06 0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
@rem 注意：PID号为13位数据必须为16进制小写表示,如 0x01ff，0x1010
@rem 所有输入的密钥数据必须为16进制小写表示,如 0x01 0xff  
@rem 所有输入的IV数据必须为16进制小写表示,如 0x01 0xff 	       	                                                          
                                                            
@rem 0x52 0x04 0x71 0xa3 0x96 0x89 0xd0 0x25 0x0b 0xe1 0x1c 0x34 0xa2 0x57 0x82 0x5c                                                                                                                     
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            