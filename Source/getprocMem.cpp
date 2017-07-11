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

#define ENT_BUFFER_LEN   4096*4

using namespace std;
ofstream outFile("/home/testcfi/Desktop/procmem.txt");

string get_procMem(){
    //FILE* uptime = popen("cat /proc/meminfo | grep \"MemFree:\"","r");  //get MemFree value
    FILE* uptime = popen("cat /proc/meminfo","r");
    ostringstream output;
    int n=0;
    int j=0;
    string value;
    char buf[ENT_BUFFER_LEN];
    while((n=fread(buf,1,ENT_BUFFER_LEN,uptime))>0){
        /*value = buf;
        value = value.erase(0,17);
        value = value.erase(value.length()-4,value.length());*/
        for(j=0;j<n;j++) {
            //outFile << buf[j] << endl;
            //2017-7-11 grep number work
            if(((int)buf[j]>=48)&&((int)buf[j]<=57)){
                outFile << buf[j];
            }
        }
    }
    outFile << endl;
    return value;
    //outFile << endl;
}

int main(){
    cout << "[+] start getprocMEM" << endl;

    for(int i=0;i<256;i++) {
        //cout<<"length:"<< get_procMem().length() <<" "<< get_procMem() << endl;
        //cout << get_procMem() << endl;
        cout << "count:" << i << endl;
        outFile << get_procMem();
        //outFile << get_procMem();
        outFile.flush();
        sleep(1);
    }
    cout << "[+] done" << endl;
    return 0;
}

