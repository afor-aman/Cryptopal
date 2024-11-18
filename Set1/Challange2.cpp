#include <iostream>
#include <bits/stdc++.h>
#include <stdio.h>

using namespace std;

void xor_doer(char x, char y){
    int dec1 = 0, dec2=0, res = 0;
    
    if(x>='0' && x<='9')
        dec1=x-48;

    if(y>='0' && y<='9')
        dec2=y-48;
    
    if(x>='A' && x<='F')
        dec1=x-55;
   
    if(y>='A' && y<='F')
        dec2=y-55;
    
    if(x>='a' && x<='f')
        dec1=x-87;
    
    if(y>='a' && y<='f')
        dec2=y-87;
    
    if(dec1<dec2)
        res = dec1 ^ dec2;
    if(dec1>dec2)
        res = dec2 ^ dec1;
    
    printf("%x", res);
}

int main(){
    string hex_str_1="", hex_str_2="";
    cin>>hex_str_1>>hex_str_2;
    int len = hex_str_1.size();
    for(int i=0;i<len;i++)
        xor_doer(hex_str_1[i], hex_str_2[i]);
    return 0;
}
