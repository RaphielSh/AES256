#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;


class AES{
    private:
        uint32_t word[60];
        uint8_t key[32];
        uint8_t plain[16];
        uint8_t roundKey[15];
        short int round;
        const uint16_t reduce = 0b100011011;
        const uint16_t mag = 0b100000000;
    public:
        AES(){};
        
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
                cout << hex << word[i] << dec << endl;
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
            
            
        }

        //  getRoundKey(int round){
            // uint32_t tmp;
            // uint8_t a,b,c,d;

            // roundKey

            // for(int i = 0; i < 15; i++){
            //     for(int j = i; j < i*4+4; j++){
            //         for(int k = 0; k < 4; k++){
            //             tmp = word[j];
            //             a = tmp >> 24;
            //             b = tmp >> 16 & 0xff;
            //             c = tmp >> 8 & 0xff;
            //             d = tmp & 0xff;
            //             roundKey[i][j][k] = a;
            //             roundKey[i][j+1][0] = b;
            //             roundKey[i][j+2][0] = c;
            //             roundKey[i][j+3][0] = d;
            //         }
            //     }

            // }
        // }

        void currentRoundKey(int rnd){
            uint32_t tmp;
            uint8_t a,b,c,d;
            for(int i = rnd*4; i < rnd*4+4; i++){
                tmp = word[i];
                
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[0] = a;
                roundKey[1] = b;
                roundKey[2] = c;
                roundKey[3] = d;
                tmp = word[i+1];
                
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[4] = a;
                roundKey[5] = b;
                roundKey[6] = c;
                roundKey[7] = d;
                tmp = word[i+2];
                
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[8] = a;
                roundKey[9] = b;
                roundKey[10] = c;
                roundKey[11] = d;
                tmp = word[i+3];
                
                a = tmp >> 24; b = tmp >> 16 & 0xff; c = tmp >> 8 & 0xff; d = tmp & 0xff;
                roundKey[12] = a;
                roundKey[13] = b;
                roundKey[14] = c;
                roundKey[15] = d;
                
            }
            // for(int i = 0; i < 16; i++) 
            //     cout << hex << roundKey[i];
            // cout << "\nEND OF KEY" << endl;
        }

        void keyAdd(){
            cout << "   Start of keyAdd cycle:" << endl;
            uint8_t tmp;
            short int count = 0;
            for(int i = 0; i < 16; i++){
                // cout <<"    start of a XOR cycle"<< endl;
                currentRoundKey(count);
                cout << "plain num = " << plain[i] << "round key = "<<roundKey[i] << endl;
                plain[i] ^= roundKey[i];
                count++;
                // print(plain);
                // cout <<"    End of a key add cycle"<< endl;
            }
            //print(plain);
            cout <<"    End of keyADD cycle"<< endl;
        }
        void subBytes(){
            cout << "   Start of subBytes cycle:" << endl;
            for(int i = 0; i < 16; i++)
                plain[i] = sBox(plain[i]);  
            //print(plain); 
        }
        void shiftRows(){
            cout << "   Start of shiftRows cycle:" << endl;
            uint8_t tmp;
            tmp = plain[1];
            plain[1] = plain[5];
            plain[5] = plain[9];
            plain[9] = plain[13];
            plain[13] = tmp;

            tmp = plain[2];
            plain[2] = plain[10];
            plain[10] = tmp;
            tmp = plain[6];
            plain[6] = plain[14];
            plain[14] = tmp;

            tmp = plain[15];
            plain[15] = plain[11];
            plain[11] = plain[7];
            plain[7] = plain[3];
            plain[3] = tmp;
            //print(plain); 
        }
        void mixColumns(){
            cout << "   Start of mix cycle:" << endl;
            uint16_t res;
            uint8_t a, b, c, d;

            for(int i = 0; i < 4; i++){
                a = plain[0 + i * 4], b = plain[1+i*4], c = plain[2+i*4], d = plain[3+i*4];

                res = (a << 1) ^ ((b << 1) ^ b) ^ c ^ d;
                if(res & mag)
                    res ^= reduce;
                plain[0 + i * 4] = res;

                res = a ^ (b << 1) ^ ((c << 1) ^ c) ^ d;
                if (res & mag)
                    res ^= reduce;
                plain[1+i*4] = res;

                res = a ^ b ^ (c << 1) ^ ((d << 1) ^ d);
                if (res & mag)
                    res ^= reduce;
                plain[2+i*4] = res;

                res = ((a << 1) ^ a) ^ b ^ c ^ (d << 1);
                if (res & mag)
                    res ^= reduce;
                plain[3+i*4] = res;
            }
            //print(plain); 
        }
        void runRound(){
            subBytes();
            shiftRows();
            mixColumns();
            keyAdd();
        }
        void encrypt(){
            
            keyAdd();
            round = 1;
            for(int i = 1; i < 14; i++){
                runRound();
                cout << "Round " << i << endl;
            }
            subBytes();
            shiftRows();
            keyAdd();
            //printPlain();
            for(int i = 0; i < 16; i++)
                cout << plain[i];
        }

        //Print Part
        // std::string hex(unsigned char inchar){
        //     std::ostringstream oss (std::ostringstream::out);
        //     oss << std::setw(2) << std::setfill('0') << std::hex << (int)(inchar);
        //     return oss.str();
        // }
        // void print(uint8_t byte){
        //     std::cout << hex(byte);
        // }
        // void printBox(uint8_t * bytes)
        // {
        //     for (int i = 0; i < 4; i++)
        //         std::cout << hex(bytes[i]) << ' ' << hex(bytes[i+4]) << ' '
        //                 << hex(bytes[i+8]) << ' ' << hex(bytes[i+12]) << std::endl;
        // }

        // void print(uint8_t * bytes)
        // {
        //     printBox(bytes);
        // }
        // void printWords(){
        //     for(int i = 0; i < 60; i++)
        //         cout << "Word[" << i << "] = " << word[i] << "\n";
        // }
        // void printKey(){
        //     cout << "\nKey is: ";
        //     for(int i = 0; i < 32; i++)
        //         cout << key[i];
        //     cout << endl;
        // }
        // void printPlain(){
        //     cout << "\nPlain Text: \n";
        //     print(plain);
        //     // for(int i = 0; i < 16; i++)
        //     //     print(plain);
        //     // cout << endl;
        // }
};






int main(){

    AES aes;

    uint8_t plainText[] = {0x32, 0x43, 0xf6, 0xa8, 
                       0x88, 0x5a, 0x30, 0x8d, 
                       0x31, 0x31, 0x98, 0xa2, 
                       0xe0, 0x37, 0x07, 0x34};

    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 
                     0x46, 0x45, 0x6B, 0x38, 0x72, 0x35, 0x6A, 0x4A, 
                     0x66, 0x63, 0x56, 0x7A, 0x4F, 0x42, 0x75, 0x4C};
    
    aes.setKey(key);
    aes.setPlain(plainText);
    // aes.printKey();
    // aes.printWords();
    // aes.printPlain();
    aes.encrypt();

    //uint32_t word[60];
    return 0;
}