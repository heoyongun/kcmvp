static int genEntropy_inner(unsigned char *buf, int len)

{

	FILE *fp, *fp2,*fp3,*fp4,*fp5;

	

#ifdef KCMVP_APPROVED

	/*fp = fopen("/dev/random", "r");

	printf("====================\nKCMVP_APPROVED\n=====================\n");

#else*/

	fp = popen("xxd -l 30 -p /dev/urandom", "r");						//OK

	//fp = fopen("/dev/random", "r");						//현재 실행시 멈춤발생

	/*2017-07-20 add*/

	fp2 = fopen("/proc/sys/kernel/random/uuid","r");		//OK

	fp3 = popen("cat /proc/timer_list | grep \"jiffies:\"","r");	//OK

	fp4 = popen("cat /proc/uptime","r");					//OK

	fp5 = fopen("/proc/meminfo" ,"r");					//OK

	

	printf("====================\nNO KCMVP_APPROVED\n====================\n");

	/*2017-07-20 add*/

#endif

	static int count = 0;

	static int all_count = 1;

	/*if( !fp ){

		printf("!fp error!\n");

		return 0;

	}*/

	/*2017-07-20*/

	if( !fp || !fp2 || !fp3 || !fp4 || !fp5){

			printf("!fp error!\n");

	}

	



	/*unsigned char* str = (unsigned char*)malloc(135);	//2017-07-20문자열 저장공간

	unsigned char* str2 = (unsigned char*)malloc(37);	//2017-07-20문자열 저장공간

	unsigned char* str3 = (unsigned char*)malloc(4096);	//2017-07-20문자열 저장공간

	unsigned char* str4 = (unsigned char*)malloc(128);	//2017-07-20문자열 저장공간

	unsigned char* str5 = (unsigned char*)malloc(10000);//2017-07-20문자열 저장공간

	*/

	char str[135];			//urandom	2017-07-25수정

	char str2[37];			//uuid

	char str3[4096];		//jiffies

	char str4[128];			//uptime

	char str5[10000];		//meminfo



	struct timeval kcmvp_time;

	

	/*2017-07-20*/

	int i;

	//==============================urandom======================

	unsigned char* temp_buf = (unsigned char*)malloc(10000);

	

	//printf("\nurandom start\n");

	if( !fread(str, 1 ,135, fp)){

		printf("!fread urandom error!\n");

	}

	char s[1024];

	for(i=0;i<strlen(str);i++){

		sprintf(s,"%02X",str[i]);

		//printf("s : %s",s);

		strcat(temp_buf,s);

	}

	printf("\n");

	

	//===========================uuid==========================



	//printf("\nuuid start\n");

	if( !fread(str2, 1, 37, fp2)){

		printf("!fread uuid error!\n");

	}

    //printf("%s\n",str2);





    str2[strlen(str2)-1]='\0';		//개행삭제

    strcat(temp_buf,str2);

    

    //==========================jiffies========================



    //printf("\njiffies start\n");

    unsigned char* str3_temp = (unsigned char*)malloc(128);

    if( !fread(str3,1,2048,fp3)){

		printf("!fread jiffies error!\n");

	}

	//printf("jiffies:");

	for(i=9;i<strlen(str3);i++){

		if(str3[i]=='\n')

			break;

		else{

			sprintf(str3_temp,"%c",str3[i]);

			//printf("%c",str3[i]);

			strcat(temp_buf,str3_temp);

		}

	}

	

    //==========================uptime=========================

    //printf("\nuptime start\n");

    if( !fread(str4,1,128,fp4)){

		printf("!fread uptime error!\n");

	}

	//printf("%s\n",str4);

	//printf("str4 length: %d\n",strlen(str4));

	str4[strlen(str4)-1]='\0';		//개행삭제

	strcat(temp_buf,str4);

	

	

	//=========================meminfo=========================



	//printf("\nmeminfo start\n");

	if( !fread(str5,1,5000,fp5)){

		printf("!fread meminfo error!\n");

	}

	int str5_count = 0;

	unsigned char* str5_temp = (unsigned char*)malloc(1024);

	

	for(i=0;i<strlen(str5);i++){

		if(((int)str5[i]>=48)&&((int)str5[i]<=57)){

			//printf("%c",str5[i]);

			//printf("if: %c",str5[i]);

			sprintf(str5_temp,"%c",str5[i]);

			//printf("s : %s",s);

			str5_count++;

			strcat(temp_buf,str5_temp);

		}

	}

	//printf("\nstr5_count: %d\n",str5_count);

	

	if(str5_count<=213){			//OS환경마다 다른 크기

		for(i=0;i<213-str5_count;i++)

			strcat(temp_buf,"0");

	}

	

	//========================sectime+usectime===================



	//printf("\ntimer start\n");

	gettimeofday(&kcmvp_time,NULL);

	char timer_sectemp[len];

	char timer_usectemp[len];

	sprintf(timer_sectemp,"%d",kcmvp_time.tv_sec);

	sprintf(timer_usectemp,"%d",kcmvp_time.tv_usec);

	strcat(temp_buf,timer_sectemp);

	strcat(temp_buf,timer_usectemp);

	//printf("%d %d\n",kcmvp_time.tv_sec,kcmvp_time.tv_usec);

	

	//===========================검사 구문================================



    printf("\n[+]check start\n");

    all_count++;

    printf("[+]before buf length: %d\n",strlen(temp_buf));

    int STATIC_LENGTH= 420;

    //unsigned char* final_temp = (unsigned char*)malloc(10);

    char final_temp[10];

    for(i=0;i<STATIC_LENGTH-strlen(temp_buf);i++){		//zero padding

    	final_temp[i]='0';

    }

    final_temp[STATIC_LENGTH-strlen(temp_buf)]='\0';

	//printf("%s",final_temp);

	strcat(temp_buf,final_temp);

	printf("[+]final buf	:	%s\n",temp_buf);

	printf("\n[+]after buf length	:	%d\n",strlen(temp_buf));

	if(strlen(temp_buf)!=STATIC_LENGTH){

		count++;

	}

    

    printf("[+]count	:	%d\n", count);

	/*2017-07-20 add*/

	printf("[+]all_count	:	%d\n", all_count);



	//===========================해시 작업================================

	/*2017-07-21*/

	//unsigned char* hash_buf = (unsigned char*)malloc(1024);

	char hash_buf[len];

	sha224(hash_buf,temp_buf,strlen(temp_buf));

	printf("==================hash===================\n");

	/*for(int i=0;i<28;i++){

		printf("%02X",hash_buf[i]);

	}*/

	//printf("buf:");

	for(i=0;i<28;i++){

		buf[i] = hash_buf[i];

		//printf("%02X",buf[i]);

	}

	//printf("\n");

	buf[17] = '\0';

	printf("after buf:");

	for(i=0;i<16;i++){

		printf("%02X",buf[i]);

	}

	printf("\n");

	//printf("\nlength: %d\n",strlen(hash_buf)); 00을 만나면 끝나게 됨

	printf("=========================================\n");

	

	fclose(fp);fclose(fp2);fclose(fp3);fclose(fp4);fclose(fp5);

	//free(str);free(str2);free(str3);free(str4);free(str5);

	//sleep(1);

	return 1;

}

#endif
