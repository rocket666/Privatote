aes 10 1 MyRec.ts MyRec_clear10.ts  0x200 0x00 0x20 0x20 0x02 0x26 0x17 0x47 0x17 0x44 0x23 0x60 0xab 0xcd 0xef 0x20 0x20 0x98 0x76 0x54 0x32 0x1a 0x12 0x34 0x56 0x78 0x9b 0xab 0xc1 0x23 0x45 0x67 0x89
@rem // ע������
@rem ����38������:
@rem 1.��ִ���ļ��� *.exe
@rem 2.AES ģʽ 0��ecb head clear; 1��ecb trail clear; 2: cbc head clear for Marlin;3: cbc trail clear for Marlin; 4: cbc cts mdi; 5: cbc cts mdd; 6: rcbc cts mdi; 7: rcbc cts mdd;8:cbc cts all;9: rcbc cts all 10��cbc dvs042 for Marlin  11��ecb cts mode
@rem 3.�������� 0:����;1:����;
@rem 4.�������ݵ��ļ���*.ts
@rem 5.д�����ݵ��ļ���*.ts 
@rem 6.PID��,16���Ʊ�ʾ  
@rem 7.��Կ��1���ֽ� 
@rem 8.��Կ��2���ֽ�
@rem 9.��Կ��3���ֽ� 
@rem 10.��Կ��4���ֽ� 
@rem 11.��Կ��5���ֽ�
@rem 12.��Կ��6���ֽ� 
@rem 13.��Կ��7���ֽ� 
@rem 14.��Կ��8���ֽ�
@rem 15.��Կ��9���ֽ� 
@rem 16.��Կ��10���ֽ� 
@rem 17.��Կ��11���ֽ�
@rem 18.��Կ��12���ֽ� 
@rem 19.��Կ��13���ֽ�
@rem 20.��Կ��14���ֽ�
@rem 21.��Կ��15���ֽ� 
@rem 22.��Կ��16���ֽ� 
@rem 23.IV��1���ֽ�
@rem 24.IV��2���ֽ�
@rem 25.IV��3���ֽ�
@rem 26.IV��4���ֽ�
@rem 27.IV��5���ֽ�
@rem 28.IV��6���ֽ�
@rem 29.IV��7���ֽ� 
@rem 30.IV��8���ֽ� 
@rem 31.IV��9���ֽ� 
@rem 32.IV��10���ֽ� 
@rem 33.IV��11���ֽ� 
@rem 34.IV��12���ֽ�
@rem 35.IV��13���ֽ� 
@rem 36.IV��14���ֽ�
@rem 37.IV��15���ֽ�
@rem 38.IV��16���ֽ� 
@rem ��:aes 0 1 1.ts 2.ts 0x203  0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06 0x7a 0xa4 0xed 0x0b 0xc5 0x82 0xbf 0x06   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
@rem ע�⣺PID��Ϊ13λ���ݱ���Ϊ16����Сд��ʾ,�� 0x01ff��0x1010
@rem �����������Կ���ݱ���Ϊ16����Сд��ʾ,�� 0x01 0xff  
@rem ���������IV���ݱ���Ϊ16����Сд��ʾ,�� 0x01 0xff 	       	                                                          
                                                            
@rem 0x52 0x04 0x71 0xa3 0x96 0x89 0xd0 0x25 0x0b 0xe1 0x1c 0x34 0xa2 0x57 0x82 0x5c                                                                                                                     
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            