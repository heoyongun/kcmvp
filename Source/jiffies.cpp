//
// Created by testcfi on 7/5/17.
//
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <fstream>
#define ENT_BUFFER_LEN      4096*4
//FILE* uptime = popen("cat /proc/timer_list | grep \"jiffies:\"","r");
using namespace std;

ofstream outFile("/home/testcfi/Desktop/jiffies.txt");
string get_jiffies(){
    FILE* uptime = popen("cat /proc/timer_list | grep \"jiffies:\"","r");
    ostringstream output;
    int n=0;
    int j=0;
    string value;
    char buf[ENT_BUFFER_LEN];
    while((n=fread(buf,1,ENT_BUFFER_LEN,uptime))>0){
        //for(j=0;j<n;j++) {
        // outFile << hex << (int)buf[j];
        //cout << buf;
        //cout <<"string:" << value << endl;
        //cout <<"after : "<< value << endl;
        //}
        value = buf;
        value = value.erase(0,9);
    }
    return value;
    //outFile << endl;
}

int main(){
    cout <<"[+] start jiffies" << endl;
    for(int i=0;i<256;i++){
        cout << get_jiffies();
        outFile << get_jiffies();
        outFile.flush();
        sleep(1);
    }
    cout <<"[+] done" << endl;
    return 0;
}
