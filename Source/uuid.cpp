//
// Created by testcfi on 7/5/17.
//
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <fstream>
//FILE* uptime = popen("cat /proc/sys/kernel/random/uuid","r");
#define ENT_BUFFER_LEN      4096*4
using namespace std;

ofstream outFile("/home/testcfi/Desktop/uuid.txt");
void get_uuid(){
    FILE* uptime = popen("cat /proc/sys/kernel/random/uuid","r");
    ostringstream output;
    int n=0;
    int j=0;
    char buf[ENT_BUFFER_LEN];
    while((n=fread(buf,1,ENT_BUFFER_LEN,uptime))>0){
        for(j=0;j<n;j++) {
            outFile << hex << (int)buf[j];
        }
    }
}

int main(){
    for(int i=0;i<256;i++){
        get_uuid();
        sleep(1);
    }
    return 0;
}
