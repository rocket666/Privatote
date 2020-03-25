des 0 1 0 Z:\symphony\ref\Tools\des_tool\ref1_3.ts Z:\symphony\ref\Tools\des_tool\ref1_4.ts 0x104 0x00 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f 0x00 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37  
@rem // 注释如下
@rem 输入39个参数:
@rem 1.可执行文件名 *.exe
@rem 2.模式 0：ecb trail clear; 1: dvs042; 2: ecb cts mode;3: ecb head clear; 4: cbc head clear; 5: cbc trail clear 6: cbc cts mdi; 7: cbc cts mdd; 8: rcbc cts mdi; 9: rcbc cts mdd
@rem 3.算法选择 0:DES;  1:TDES;
@rem 4.操作类型 0:加扰; 1:解扰;
@rem 5.读出数据的文件名*.ts
@rem 6.写入数据的文件名*.ts 
@rem 7.PID号,16进制表示  
@rem 8.KEY1第1个字节 
@rem 9.KEY1第2个字节 
@rem 10.KEY1第3个字节 
@rem 11.KEY1第4个字节
@rem 12.KEY1第5个字节 
@rem 13.KEY1第6个字节 
@rem 14.KEY1第7个字节 
@rem 15.KEY1第8个字节 
@rem 16.KEY2第1个字节 
@rem 17.KEY2第2个字节 
@rem 18.KEY2第3个字节 
@rem 19.KEY2第4个字节
@rem 20.KEY2第5个字节 
@rem 21.KEY2第6个字节 
@rem 22.KEY2第7个字节 
@rem 23.KEY2第8个字节 
@rem 24.KEY3第1个字节 
@rem 25.KEY3第2个字节 
@rem 26.KEY3第3个字节 
@rem 27.KEY3第4个字节
@rem 28.KEY3第5个字节 
@rem 29.KEY3第6个字节 
@rem 30.KEY3第7个字节 
@rem 31.KEY3第8个字节 
@rem 32.IV第1个字节
@rem 32.IV第2个字节 
@rem 34.IV第3个字节 
@rem 35.IV第4个字节 
@rem 36.IV第5个字节 
@rem 37.IV第6个字节 
@rem 38.IV第7个字节 
@rem 39.IV第8个字节
@rem 例:des 0 0 1 1.ts 2.ts 0x203 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8    0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18    0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28  0xa 0xb 0xc 0xd 0x1 0x2 0x3 0x4 
@rem 注意：PID号为13位数据必须为16进制小写表示,如 0x01ff，0x1010
@rem 所有输入的密钥数据必须为16进制小写表示,如 0x01 0xff  
@rem 所有输入的IV数据必须为16进制小写表示,如 0x01 0xff  	       	                                                          
                                                            
@rem 0x52 0x04 0x71 0xa3 0x96 0x89 0xd0 0x25 0x0b 0xe1 0x1c 0x34 0xa2 0x57 0x82 0x5c                                                                                                                     
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            