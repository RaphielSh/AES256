#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
using namespace std;


class AES{
    private:
        //to encrypt
        uint32_t word[60];
        uint8_t key[32];
        uint8_t plain[16];
        uint8_t roundKey[15][16];
        short int round = 0;
        const uint16_t reduce = 0b100011011;
        const uint16_t mag = 0b100000000;
        //CBC vars
        uint8_t initVector[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
                                0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
        uint8_t prevBlock[16];

        //to decrypt
        string out;
        uint8_t encrypted[16];
    public:
        AES(){};

        //ENCRYPT//

        //Substitutions and constants

        uint8_t sBox(uint8_t byte){
            uint8_t s[256] ={
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
            return s[byte];
        }

        uint8_t invSBox(uint8_t byte){
            uint8_t sInv[256] ={
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};
            return sInv[byte];
        }
        uint8_t Rcon(uint8_t byte){
            uint8_t r[11] ={0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
        return r[byte];
        }

        //Setters
        void setKey(uint8_t *bytes){
            for(int i = 0; i < 32; i++)
                key[i] = bytes[i];
            keyExpand();
        };
        void setPlain(uint8_t *bytes){
            for(int i = 0; i < 16; i++)
                plain[i] = bytes[i];
        }

        //Functions
        uint32_t rotWord(uint32_t round_w){
            uint8_t a, b, c, d;

            // 0x344a5f4e
            a = round_w >> 24; // 0x34
            b = round_w >> 16 & 0xff; // 0x4a
            c = round_w >> 8 & 0xff; // 5f
            d = round_w & 0xff; // 4e

            round_w = b << 24 | c << 16 | d << 8 | a;
            return round_w;
        }

        void keyExpand(){
            uint8_t a,b,c,d;
            uint32_t tmp;
            //First 8 words
            for(int i = 0; i < 8; i++){
                word[i] = key[4*i] << 24 | key[4*i+1] << 16 | key[4*i+2] << 8 | key[4*i+3];
                //cout << "   ->Word[" << i << "] = " << hex << word[i] << dec << endl;
            }

            //Making schedule of next 52 words
            for(int i = 8; i < 60; i++){
                tmp = word[i-1];
                if(i % 8 == 0){
                    tmp = rotWord(tmp);
                    a = tmp >> 24;
                    b = tmp >> 16 & 0xff;
                    c = tmp >> 8 & 0xff;
                    d = tmp & 0xff;
                    sBox(a); a ^= Rcon(i/8);
                    sBox(b); b ^= Rcon(i/8);
                    sBox(c); c ^= Rcon(i/8);
                    sBox(d); d ^= Rcon(i/8);
                    tmp = a << 24 | b << 16 | c << 8 | d;
                }
                else if(i % 8 == 4){
                    a = tmp >> 24; sBox(a);
                    b = tmp >> 16 & 0xff; sBox(b);
                    c = tmp >> 8 & 0xff; sBox(c);
                    d = tmp & 0xff; sBox(d);
                    tmp = a << 24 | b << 16 | c << 8 | d;
                }
                word[i] = word[i-8] ^ tmp;
                //cout << "Word[" << i << "] = "<< hex(word[i]) << endl;
            }
            initRoundKeys();

        }

        void initRoundKeys(){
            uint32_t tmp;
            uint8_t a,b,c,d;
            for(int i = 0; i < 15; i++){
                tmp = word[i*4];
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[i][0] = a;
                roundKey[i][1] = b;
                roundKey[i][2] = c;
                roundKey[i][3] = d;

                tmp = word[i*4+1];
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[i][4] = a;
                roundKey[i][5] = b;
                roundKey[i][6] = c;
                roundKey[i][7] = d;

                tmp = word[i*4+2];
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[i][8] = a;
                roundKey[i][9] = b;
                roundKey[i][10] = c;
                roundKey[i][11] = d;

                tmp = word[i*4+3];
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[i][12] = a;
                roundKey[i][13] = b;
                roundKey[i][14] = c;
                roundKey[i][15] = d;
            }
        }

        void savePrev(){
            for(int i = 0; i < 16; i++)
                prevBlock[i] = plain[i];
        }
        void chainXOR(){
            for(int i = 0; i < 16; i++){
                plain[i] ^= prevBlock[i];
            }
        }

        void dectyptRound(){
            cout << "\n    ->Inv Key Add: " << endl;
            invKeyAdd();
            print(plain);
            cout << "\n    ->Current key is: " << endl;
            printCurrRoundKey(round);
            cout << "\n    ->invShiftRows" << endl;
            invShiftRows();
            print(plain);
            cout << "\n    ->invMixColumns" << endl;
            invMixColumns();
            print(plain);
            cout << "\n    ->invSubBytes" << endl;
            invSubBytes();
            print(plain);
        }

        void decrypt(){
            cout << "Before decrypt" << endl;
            print(plain);
            round = 0;

            invKeyAdd();
            invShiftRows();
            invSubBytes();
            round++;

            for(int i = 0; i < 14; i++){
                cout << "Round " << i << endl;
                dectyptRound();
                round++;
            }
            cout << "Last 14 round operations:" << endl;
            invKeyAdd();

            cout << "\nDecrypted text: " << endl;
            for(int i = 0; i < 16; i++){
                cout << hex(plain[i]) <<  " ";
                out += plain[i];
            }

        }

        //DECRYPTOR//


        void invShiftRows(){
           uint8_t tmp;
           tmp = encrypted[13];
           encrypted[13] = encrypted[9];
           encrypted[9] = encrypted[5];
           encrypted[5] = encrypted[1];
           encrypted[1] = tmp;

           tmp = encrypted[2];
           encrypted[2] = encrypted[10];
           encrypted[10] = tmp;
           tmp = encrypted[6];
           encrypted[6] = encrypted[14];
           encrypted[14] = tmp;

           tmp = encrypted[3];
           encrypted[3] = encrypted[7];
           encrypted[7] = encrypted[11];
           encrypted[11] = encrypted[15];
           encrypted[15] = tmp;
        }
        void invSubBytes(){
            for(int i = 0; i < 16; i++)
                plain[i] = invSBox(plain[i]);
        }

        uint8_t mul (uint16_t num, uint8_t mul){
            uint8_t res = 0;
            for (int i = 0; i < 8; i++){
                if (mul & (1 << i))
                    res ^= num;
                num <<= 1;
                if (num & 0x100)
                    num ^= 0b11011;
            }
            return res;
        }

        void invMixColumns(){
            uint16_t res;
            uint8_t a,b,c,d;

            for (int i = 0; i < 4; i++){
                a = plain[0+i*4], b = plain[1+i*4], c = plain[2+i*4], d = plain[3+i*4];

                res = mul(a, 0xE) ^ mul(b, 0xB) ^ mul(c, 0xD) ^ mul(d, 0x9);
                if (res & mag)
                    res ^= reduce;
                plain[0+i*4] = res;

                res = mul(a, 0x9) ^ mul(b, 0xE) ^ mul(c, 0xB) ^ mul(d, 0xD);
                if (res & mag)
                    res ^= reduce;
                plain[1+i*4] = res;

                res = mul(a, 0xD) ^ mul(b, 0x9) ^ mul(c, 0xE) ^ mul(d, 0xB);
                if (res & mag)
                    res ^= reduce;
                plain[2+i*4] = res;

                res = mul(a, 0xB) ^ mul(b, 0xD) ^ mul(c, 0x9) ^ mul(d, 0xE);
                if (res & mag)
                    res ^= reduce;
                plain[3+i*4] = res;
            }
        }

        void invKeyAdd(){
            for(int i = 0; i < 16; i++)
                plain[i] ^= roundKey[14-round][i];
        }
       


        //Getters
        string getPlain(){return out;}

        //Print Part
        std::string hex(unsigned char inchar){
            std::ostringstream oss (std::ostringstream::out);
            oss << std::setw(2) << std::setfill('0') << std::hex << (int)(inchar);
            return oss.str();
        }
        void print(uint8_t byte){
            std::cout << hex(byte);
        }
        void printInit(){
            cout << "Init Vector: ";
            for(int i = 0; i < 16; i++)
                cout << initVector[i];
            cout << endl;
        }
        void printBox(uint8_t * bytes)
        {
            for (int i = 0; i < 4; i++)
                std::cout << hex(bytes[i]) << ' ' << hex(bytes[i+4]) << ' '
                        << hex(bytes[i+8]) << ' ' << hex(bytes[i+12]) << std::endl;
        }

        void print(uint8_t * bytes)
        {
            printBox(bytes);
        }
        void printWords(){
            for(int i = 0; i < 60; i++)
                cout << "Word[" << i << "] = " << word[i] << "\n";
        }
        void printKey(){
            cout << "\nKey is: ";
            for(int i = 0; i < 32; i++)
                cout << key[i];
            cout << endl;
        }
        void printPlain(){
            cout << "\nPlain Text: \n";
            print(plain);
            // for(int i = 0; i < 16; i++)
            //     print(plain);
            // cout << endl;
        }
        void printCurrRoundKey(int rnd){
            for (int i = 0; i < 16; i++)
                cout << hex(roundKey[rnd][i]) << " ";
        }
};

int main(){

    AES aes;
    //string vars
    string plainIn, input_file, output_file;
    cout << "File name to decrypt" << endl;
    getline(cin, input_file);
    output_file = "decrypted_";
    ifstream infile(input_file, ios::binary | ios::in);    
    ofstream outfile(output_file + input_file, ios::binary|ios::out);
    char buffer;

    //put file in string
    while(infile >> noskipws >> buffer) plainIn += buffer; 
    
    infile.close();
    
    int sizeOfPlain =  plainIn.size();
    short int pureCount = sizeOfPlain/16;
    short int lastChars = sizeOfPlain - (16*pureCount);
    uint8_t plainText[pureCount][16];
    int tmp = 0;
    int count = 0;

    //key vars

    string keyIn;
    cout << "Type a key you want the text to be decrypted with: " << endl;
    getline(cin, keyIn);
    vector<uint8_t> keyVector(keyIn.begin(), keyIn.end());
    uint8_t key[32];

    //Check if key is 32 bit
    if(keyIn.length() < 32){
        cout << "Key must be 32 bit.";
        return 1;
    }
    else if(keyIn.length() > 32){
        cout << "Key must be 32 bit.";
        return 1;
    }
    else{
        for(int i = 0; i < 32; i++)
            key[i] = keyVector[i];
    }

    vector<uint8_t> plainVector(plainIn.begin(), plainIn.end());

    cout << "Number of int 16 blocks = " << pureCount<<endl;
    cout << "Not fitted count = " << lastChars<<endl;
    cout << "Size of plain = " << sizeOfPlain << endl;
    cout << "Key = " << key << endl;
    aes.printInit();

    // If text is bigger then 16 characters we need to split it to multiple arrays of 16 values
    if(sizeOfPlain > 16){
        for(int i = 0; i < pureCount; i++){
            for(int j = 0; j < 16; j++){
                plainText[i][j] = plainVector[tmp];
                tmp++;
            }
        }
        //Here we add characters that are smaller then 16-digit array to one more array and add zeroes
        //If we have text with 20 chars we need to put 16 first chars to one array and last 4 chars in the second array and add 16 zeroes to it
        if(lastChars % 16 != 0){
            tmp = sizeOfPlain - lastChars;
            cout << "Tmp: " << tmp << endl;
            for(int i = 0; i < lastChars; i++)
                plainText[pureCount][i] = plainVector[tmp+i];
            for(int i = lastChars+1; i < 16; i++)
                plainText[pureCount][i] = 0;
        }
        
    }
    //If we have text smaller or equal 16 we just need to put it in plaintext[0] and add zeroes if it neccessary
    else if(sizeOfPlain < 16){
        for(int i = 0; i < sizeOfPlain; i++)
            plainText[0][i] = plainVector[i];
        for(int i = lastChars; i < 16; i++)
            plainText[0][i] = 0;
        //Print
        for(int i = 0; i < 16; i++)
            cout << plainText[0][i] << " ";
    }
    
    
    for(int i = 0; i < 16; i++)
        cout << plainText[0][i] << " ";
    aes.setKey(key);

    //Decryption

    for(int i = 0; i <= pureCount; i++){
        aes.setPlain(plainText[i]);
        aes.decrypt();
    }

    outfile << aes.getPlain();
    outfile.close();
    return 0;
}
