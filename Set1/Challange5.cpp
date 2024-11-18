#include <iostream>
#include <bits/stdc++.h>
#include <stdio.h>
#include <string>

using namespace std;

int main(){
    string str = "";
    string FIX = "ICE";
    int y=0;
    int res=0;
    int len;
    int t=2;
    while (t--) 
    { 
        getline(cin, str); 
        
        len = str.size();
        for(int i=0;i<len;i++){
            if (int(str[i]) == 13)
                res = '\n' ^ FIX[y];
            else
                res = str[i] ^ FIX[y];
            cout<<hex<<std::setfill('0') << std::setw(2)<<res;
            if(y<2)
                y++;
            else
                y=0;
        }
    } 
    
    return 0;
}
