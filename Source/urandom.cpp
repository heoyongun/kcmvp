//
// Created by testcfi on 7/5/17.
//
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>

#define ENT_BUFFER_LEN      4096*4
using namespace std;

ofstream outFile("/home/testcfi/Desktop/urandom.txt");
//FILE* uptime = popen("head -c 15 /dev/random | mmencode","r");
void get_random(){
    FILE* uptime = popen("head -c 32 /dev/urandom","r");    //2017-7-11 without mmencode
    ostringstream output;
    int n=0;
    int j=0;
    char buf[ENT_BUFFER_LEN];
    while((n=fread(buf,1,ENT_BUFFER_LEN,uptime))>0){
        for(j=0;j<n;j++) {
            outFile << buf[j];
        }
    }
    outFile << endl;    //2017-7-11 add endl (if not bitcode can erase it)
    outFile.flush();
}

int main(){
    cout << "[+] start urandom" << endl;
    for(int i=0;i<256;i++){
        get_random();
        cout << "count:" << i << endl;
        sleep(1);
    }
    cout << "[+] done" << endl;
    outFile.close();
}
