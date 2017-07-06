#include <iostream>
#include <sys/time.h>
#include <fstream>
#include <unistd.h>
using namespace std;

struct timeval kcmvp_time;

void kcmvptimer() {
    gettimeofday(&kcmvp_time, NULL);
    ofstream sec_file("/home/testcfi/Desktop/sectime.txt", ios::app);
    ofstream usec_file("/home/testcfi/Desktop/usectime.txt", ios::app);
    sec_file <<(long int) kcmvp_time.tv_sec << endl;
    usec_file<<(long int) kcmvp_time.tv_usec << endl;
    sec_file.flush();
    usec_file.flush();
    sec_file.close();
    usec_file.close();
}

int main() {
    cout<<"tv_usec size:"<<sizeof(kcmvp_time.tv_usec)<<endl;
    cout<<"tv_sec_size:"<<sizeof(kcmvp_time.tv_sec)<<endl;
    for(int i=0;i<256;i++){
        kcmvptimer();
        sleep(1);
    }
    cout<<"[+] done"<<endl;
    return 0;
}

/*
 for (i=0; i<sizeof(tv); i++)
    fprintf(fp_tmp, "%02x", *((unsigned char*)&tv+i));
 fputs("\n", fp_tmp);
 fflush(fp_tmp);
 break;

 */