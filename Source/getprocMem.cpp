//
// Created by testcfi on 7/5/17.
//

/*
 * 8. getprocMEM
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <cctype>

#define ENT_BUFFER_LEN      4096*4

using namespace std;
ofstream outFile("/home/testcfi/Desktop/procmem.txt");

void get_procMem(){
    FILE* uptime = popen("cat /proc/meminfo","r");
    ostringstream output;
    int n=0;
    int j=0;
    char buf[ENT_BUFFER_LEN];
    while((n=fread(buf,1,ENT_BUFFER_LEN,uptime))>0){
        for(j=0;j<n;j++) {
            outFile << hex << (int)buf[j];
        }
    }
    outFile << endl;
}

int main(){
    cout << "[+] start" << endl;

    for(int i=0;i<256;i++) {
        get_procMem();
        sleep(1);
    }
    cout << "[+] done" << endl;
    return 0;
}

