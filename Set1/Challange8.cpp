//Link to file.txt->https://cryptopals.com/static/challenge-data/8.txt
#include <iostream>
#include <bits/stdc++.h>
#include <fstream>
using namespace std;

int main(){
	string line;
	int chunk = 16;
	string res="";
	int index=0;
	map<string, int> m;
	vector<string> v;
	ifstream f ("file.txt");

	while(getline(f, line)){
		int s = line.size();
		s = s/16; //320%16 = 20block of 16-bytes
		for(int i=0;i<s;i++){
			res = line.substr(index,chunk);
			v.push_back(res);
			index+=16;
		}
		
		for (auto & elem : v)
		{
    		auto result = m.insert(std::pair<std::string, int>(elem, 1));
    		if (result.second == false)
        	result.first->second++;
		}

		for (auto & elem : m)
		{
    		if (elem.second > 1)
    		{
        		std::cout << elem.first << " :: " << elem.second << std::endl;
				    break;
    		}
		}	

		v.clear();
		m.clear();
		index=0;
	}
		
	return 0;
}
