#include <iostream>
#include <string>
#include <cstdint>

using namespace std;

// Initial Permutation Table
const int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

// Final Permutation Table
const int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

// Expansion Table
const int E[] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// Permutation P
const int P[] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

// Permuted Choice 1
const int PC1[] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

// Permuted Choice 2
const int PC2[] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// Shift schedule
const int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// S-Boxes
const int S[8][4][16] = {
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
     {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
     {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
     {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
     {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
     {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
     {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
     {7,11,4,1,9,12,14,2,0,5,10,3,13,8,15,6},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

uint64_t permute(uint64_t input, const int* table, int n) {
    uint64_t output = 0;
    for (int i = 0; i < n; i++) {
        output <<= 1;
        output |= (input >> (64 - table[i])) & 1;
    }
    return output;
}

uint32_t leftShift(uint32_t k, int shifts) {
    return ((k << shifts) | (k >> (28 - shifts))) & 0x0FFFFFFF;
}

void generateKeys(uint64_t key, uint64_t* subkeys) {
    uint64_t permutedKey = permute(key, PC1, 56);
    uint32_t C = (permutedKey >> 28) & 0x0FFFFFFF;
    uint32_t D = permutedKey & 0x0FFFFFFF;
    
    for (int i = 0; i < 16; i++) {
        C = leftShift(C, shifts[i]);
        D = leftShift(D, shifts[i]);
        uint64_t CD = ((uint64_t)C << 28) | D;
        subkeys[i] = permute(CD, PC2, 48);
    }
}

uint32_t sBoxSubstitution(uint64_t input) {
    uint32_t output = 0;
    for (int i = 0; i < 8; i++) {
        int sixBits = (input >> (42 - 6 * i)) & 0x3F;
        int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
        int col = (sixBits >> 1) & 0x0F;
        int val = S[i][row][col];
        output = (output << 4) | val;
    }
    return output;
}

uint32_t feistel(uint32_t R, uint64_t subkey) {
    uint64_t expandedR = 0;
    for (int i = 0; i < 48; i++) {
        expandedR <<= 1;
        expandedR |= (R >> (32 - E[i])) & 1;
    }
    
    uint64_t xorResult = expandedR ^ subkey;
    uint32_t sBoxOutput = sBoxSubstitution(xorResult);
    
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        result <<= 1;
        result |= (sBoxOutput >> (32 - P[i])) & 1;
    }
    return result;
}

uint64_t desProcess(uint64_t input, uint64_t key, bool encrypt) {
    uint64_t subkeys[16];
    generateKeys(key, subkeys);
    
    uint64_t permutedText = permute(input, IP, 64);
    uint32_t L = (permutedText >> 32) & 0xFFFFFFFF;
    uint32_t R = permutedText & 0xFFFFFFFF;
    
    for (int i = 0; i < 16; i++) {
        int keyIndex = encrypt ? i : 15 - i;
        uint32_t temp = R;
        R = L ^ feistel(R, subkeys[keyIndex]);
        L = temp;
    }
    
    uint64_t combined = ((uint64_t)R << 32) | L;
    return permute(combined, FP, 64);
}

uint64_t hexToUint64(const string& hex) {
    uint64_t result = 0;
    for (char c : hex) {
        result <<= 4;
        if (c >= '0' && c <= '9') result |= c - '0';
        else if (c >= 'a' && c <= 'f') result |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') result |= c - 'A' + 10;
    }
    return result;
}

string uint64ToHex(uint64_t value) {
    string hex = "";
    for (int i = 0; i < 16; i++) {
        int digit = (value >> (60 - 4 * i)) & 0xF;
        hex += (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
    }
    return hex;
}

bool isValidHex(const string& str) {
    if (str.length() != 16) return false;
    for (char c : str) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

bool isHexString(const string& str) {
    if (str.length() != 16) return false;
    for (char c : str) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

uint64_t stringToKey(const string& str) {
    if (str.length() > 8) {
        cout << "Warning: String too long, truncated to 8 characters." << endl;
    }
    
    uint64_t key = 0;
    for (int i = 0; i < 8 && i < str.length(); i++) {
        key = (key << 8) | (unsigned char)str[i];
    }
    
    // Pad with zeros if less than 8 characters
    if (str.length() < 8) {
        key <<= (8 - str.length()) * 8;
    }
    
    return key;
}

int main() {
    int choice;
    string input, key;
    
    while (true) {
        cout << "\n=== DES Encryption/Decryption ===" << endl;
        cout << "1. Encrypt" << endl;
        cout << "2. Decrypt" << endl;
        cout << "3. Both (Encrypt & Decrypt)" << endl;
        cout << "4. Exit" << endl;
        cout << "Choice: ";
        cin >> choice;
        
        if (choice == 4) break;
        if (choice < 1 || choice > 4) {
            cout << "Invalid option!" << endl;
            continue;
        }
        
        cout << "Key (16 hex or 8 characters): ";
        cin >> key;
        
        uint64_t keyValue;
        
        if (isHexString(key)) {
            // Input is hexadecimal
            keyValue = hexToUint64(key);
            cout << "Detected: HEX key" << endl;
        } else {
            // Input is ASCII string
            if (key.length() > 8) {
                cout << "String key too long! Max 8 characters." << endl;
                continue;
            }
            keyValue = stringToKey(key);
            cout << "Detected: ASCII string key" << endl;
            cout << "Key in HEX: " << uint64ToHex(keyValue) << endl;
        }
        
        if (choice == 1) {
            cout << "Plaintext (16 hex): ";
            cin >> input;
            if (!isValidHex(input)) {
                cout << "Invalid input!" << endl;
                continue;
            }
            uint64_t plaintext = hexToUint64(input);
            uint64_t ciphertext = desProcess(plaintext, keyValue, true);
            cout << "\nCiphertext: " << uint64ToHex(ciphertext) << endl;
            
        } else if (choice == 2) {
            cout << "Ciphertext (16 hex): ";
            cin >> input;
            if (!isValidHex(input)) {
                cout << "Invalid input!" << endl;
                continue;
            }
            uint64_t ciphertext = hexToUint64(input);
            uint64_t plaintext = desProcess(ciphertext, keyValue, false);
            cout << "\nPlaintext: " << uint64ToHex(plaintext) << endl;
            
        } else if (choice == 3) {
            cout << "Plaintext (16 hex): ";
            cin >> input;
            if (!isValidHex(input)) {
                cout << "Invalid input!" << endl;
                continue;
            }
            uint64_t plaintext = hexToUint64(input);
            uint64_t ciphertext = desProcess(plaintext, keyValue, true);
            uint64_t decrypted = desProcess(ciphertext, keyValue, false);
            
            cout << "\nPlaintext:  " << input << endl;
            cout << "Ciphertext: " << uint64ToHex(ciphertext) << endl;
            cout << "Decrypted:  " << uint64ToHex(decrypted) << endl;
            cout << (decrypted == plaintext ? "SUCCESS!" : "FAILED!") << endl;
        }
    }
    
    return 0;
}