//
// Created by testcfi on 7/5/17.
//
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>

#define ENT_BUFFER_LEN      4096*4
using namespace std;

ofstream outFile("/home/testcfi/Desktop/random.txt");
//FILE* uptime = popen("head -c 15 /dev/random | mmencode","r");
void get_random(){
    FILE* uptime = popen("head -c 15 /dev/random | mmencode","r");
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
    outFile.flush();
}

int main(){

    for(int i=0;i<256;i++){
        get_random();
        sleep(1);
    }
    outFile.close();
}
