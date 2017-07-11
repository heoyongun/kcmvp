#include <iostream>
#include <sys/time.h>
#include <fstream>
#include <unistd.h>
#include <iomanip>

using namespace std;

struct timeval kcmvp_time;

ofstream usec_file("/home/testcfi/Desktop/usectime.txt");
void kcmvptimer() {
    gettimeofday(&kcmvp_time, NULL);
    usec_file<< kcmvp_time.tv_usec << endl;
    usec_file.flush();
}

int main() {
    cout << "[+] start kcmvptimer" << endl;
    for(int i=0;i<256;i++){
        kcmvptimer();
        cout << "count:" << i << endl;
        sleep(1);
    }
    cout<<"[+] done"<<endl;
    return 0;
}