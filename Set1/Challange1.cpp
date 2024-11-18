#include <iostream>
#include <bits/stdc++.h>

using namespace std;

int bin_to_dec(string bin_str){
    string num = bin_str; 
    int dec_value = 0; 
    int base = 1; 
    int len = num.length(); 
    for (int i = len - 1; i >= 0; i--) { 
        if (num[i] == '1') 
            dec_value += base; 
        base = base * 2; 
    }
    return dec_value; 
}

void ascii_to_base_64(string ascii){
    string char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = ascii.size();
    int rem_len = 0;
    int i=0;
    string bin_str = "";
    string base64 = "";
    string part = "";
    cout<<'\n';
    while(len--){
        char single = ascii[i];
        bin_str+=bitset<8>(single).to_string();
        i++;
    }
    i=0;
    for(;;){
        part = bin_str.substr(i,6);
        if(part.size()<6)
            break;
        base64+=char_set[bin_to_dec(part)];
        i+=6;
    }
    rem_len = part.size();
    if(rem_len>0){
        int rem = 6-rem_len;
        rem_len = rem;
        while(1){
            part+="00";
            rem-=2;
            if(rem == 0)
                break;
        }
        base64+=char_set[bin_to_dec(part)];
        if(rem_len > 2)
            base64+="==";
        else
            base64+="=";
    }
    cout<<"Coverted String to Base64: "<<base64;
}

string hex_to_ascii(string hex_str){
    cout<<"Entered hex string: "<<hex_str<<'\n';
    string ascii = "";
   for (size_t i = 0; i < hex_str.length(); i += 2)
   {
      string part = hex_str.substr(i, 2);
      char ch = stoul(part, nullptr, 16);
      ascii += ch;
   }
   return ascii;
}

int main(){
    string hex_str="";
    cin>>hex_str;
    string converted = hex_to_ascii(hex_str);
    cout<<"Hex to ascii: "<<converted;
    ascii_to_base_64(converted);
    return 0;
}