#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <string>

#define ENT_BUFFER_LEN      4096*4

using namespace std;
//FILE* uptime = popen("cat /proc/uptime","r");
ofstream outFile("/home/testcfi/Desktop/uptime.txt");
void get_uptime(){
    FILE* uptime = popen("cat /proc/uptime","r");
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
    cout<<"[+] start uptime"<<endl;
    for(int i=0;i<256;i++){
        get_uptime();
        sleep(1);
    }
    cout<<"[+] done" << endl;
}