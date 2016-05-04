#include "attack.h"
#include "math.h"
#include "time.h"
#include "limits.h"
#include "ctype.h"

#define BUFFER_SIZE ( 80 )

pid_t pid        = 0;    // process ID (of either parent or child) from fork
int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker
FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream
FILE* data_in  = NULL; //.conf file

#define OCTET 16
#define MAX_NUM 256

int interaction= 0;
//Plaintext
char* pt  = "3243F6A88857308D31319851E0370732";
//char* pt  = "3243F6A8885A308D313198A2E0370734";
char* pt2 = "00112233445566778899AABBCCDDEEFF";
//Ciphertexts storage
int x[OCTET]={0};
int y[OCTET]={0};
int x_2[OCTET]={0};
int y_2[OCTET]={0};
//Array to store the final key value found
int keyArray[OCTET]={0};

//inverse S-box lookup table
int inv_s[256] =
 {
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
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
 };
//Function to generate fault specification
char* faultSpec( const int r, const int f, const int p, const int i, const int j){
  int size = 9;
  if (r > 9) size++;
  char* result= malloc(sizeof(char)*size);
  if (result == NULL) exit(0);
  char sub[8];
  if (r > 9) {
    result[0]='1';
    result[1]='0';
    result[2]=',';
    result[3]='\0';
  }
  else{
    result[0] = r+'0';
    result[1]=',';
    result[2]='\0';
  }
  sub[0] = f+'0';
  sub[1] = ',';
  sub[2] = p+'0';
  sub[3] = ',';
  sub[4] = i+'0';
  sub[5] = ',';
  sub[6] = j+'0';
  sub[7] = '\0';
  strcat(result, sub);
  return result;
}
void interact(  mpz_t c, const char* spec, const char* m){
  //Send spec and m
  gmp_fprintf(target_in, "%s\n", spec); fflush(target_in);
  gmp_fprintf(target_in, "%s\n", m); fflush(target_in);
  //Receive c from target
  if (gmp_fscanf(target_out, "%ZX", c) == 0) { abort(); }
  interaction++;
}

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet = NULL;
  int size = 2*OCTET;
  int l = mpz_sizeinbase(i, 16);
  octet = malloc(size+1);
  if (octet==NULL)exit(0);

  char* tmpStr = NULL;
  tmpStr = mpz_get_str(tmpStr, 16, i);
  int index = 0;
  for (index = 0; index<=(size-l) ;index++){
    octet[index] = '0';
  }
  int m = 0;
  for (int k = index-1;k<size;k = k+1){
    octet[k] = toupper(tmpStr[m]);
    m++;
  }
  octet[size] = '\0';
  return octet;
}

//Convert octet string to integer
void oct2int(mpz_t i, const char* string){
  mpz_set_str(i, string, 16);
}

//Compare two sets of key hypothesis
//Return 1 if unique key is found.
int compareKeys(int* key, int* a1, int* a2, int* a3, int* a4, int* b1, int* b2, int* b3, int* b4){
  int count=0;
  for (int i = 0;i<MAX_NUM;i++){
    if (a1[i]== -1 || a2[i]== -1 || a3[i]== -1 || a4[i]== -1 ) break;
    for (int j = 0;j<MAX_NUM;j++){
      if (b1[j]== -1 || b2[j]== -1 || b3[j]== -1 || b4[j]== -1 ) break;
      if (a1[i] != b1[j])continue;
      if (a2[i] != b2[j])continue;
      if (a3[i] != b3[j])continue;
      if (a4[i] != b4[j])continue;
      count++;
      if (count == 1) {
        key[0] = a1[i];
        key[1] = a2[i];
        key[2] = a3[i];
        key[3] = a4[i];
      }
    }
  }
  return count;
}

//Compute Polynomial Multiplication of a and b
int polymul(int a, int b){
  int p = 0;
  while(b){
    if (b & 1) p = p^a;
    if (a & 0x80) a = (a<<1)^0x11b;
    else a <<=1;
    b >>= 1;
  }
  return p;
}
//Function to solve equations and find the key hypothesis
//inv_s[c1^k1]^inv_s[cf1^k1] = 2(inv_s[c4^k4]^inv_s[cf4^k4])
//inv_s[c4^k4]^inv_s[cf4^k4] = (inv_s[c3^k3]^inv_s[cf3^k3])
//inv_s[c2^k2]^inv_s[cf2^k2] = 3(inv_s[c4^k4]^inv_s[cf4^k4])
//Find k1, k2, k3 and k4
void findK(int c1, int c2, int c3, int c4,
    int cf1, int cf2, int cf3, int cf4,
      int* k1, int* k2, int* k3, int*k4){
  int index = 0;
  //guess k1 and k14
  for (int i1 = 0;i1<MAX_NUM;i1++){
    for (int i4 = 0;i4<MAX_NUM;i4++){
      int lhs1 = inv_s[c1^i1]^inv_s[cf1^i1];
      int rhs1 = inv_s[c4^i4]^inv_s[cf4^i4];
      if (lhs1 == polymul(2, rhs1)){
        //guess k11
        for (int i3 = 0;i3<MAX_NUM;i3++){
          int rhs2 = inv_s[c3^i3]^inv_s[cf3^i3];
          if (rhs1 == rhs2){
            //guess k8
            for (int i2 = 0;i2<MAX_NUM;i2++){
              int lhs2 = inv_s[c2^i2]^inv_s[cf2^i2];
              //if all three equations are satisfied...
              if (lhs2 == polymul(3, rhs1)){
                k1[index] = i1;
                k2[index] = i2;
                k3[index] = i3;
                k4[index] = i4;
                index++;
              }
            }
          }
        }
      }
    }
  }
  if (index>255) index = 255;
    k1[index] = -1;
    k2[index] = -1;
    k3[index] = -1;
    k4[index] = -1;
}

//Function to convert octet string into state matrix
void convertToIntArray(int* array, char* ct){
  static char tmp[3];
  tmp[2] = '\0';
  //Take two letters from string and store it in matrix
  for (int i = 0;i<strlen(ct);i=i+2){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      array[(i/2)]=(int)strtol(tmp, NULL, 16);
  }
}
//Function to find the solution of three equations generated by inducing a fault in 8th round
//Arguments are decided by following the equations
int findSolution(int x1, int x2, int x3, int x4){
    //Storage for first fault ciphertext
    static int keySto1[MAX_NUM]={0}; //storage for byte 1,  12, 3, 10
    static int keySto2[MAX_NUM]={0}; //storage for byte 8,  15, 6, 13
    static int keySto3[MAX_NUM]={0}; //storage for byte 11, 2,  16, 4
    static int keySto4[MAX_NUM]={0}; //storage for byte 14, 5,  9,  7
    //Storage for second fault ciphertext
    static int keySto1_2[MAX_NUM]={0};
    static int keySto2_2[MAX_NUM]={0};
    static int keySto3_2[MAX_NUM]={0};
    static int keySto4_2[MAX_NUM]={0};
    static int key[4]={0};
    //Find key hypothesis for first fault ciphertext
    findK(x[x1], x[x2], x[x3], x[x4],
      y[x1], y[x2], y[x3], y[x4],
      keySto1, keySto2, keySto3, keySto4 );
    //Find key hypothesis for second fault ciphertext
    findK(x_2[x1], x_2[x2], x_2[x3], x_2[x4],
      y_2[x1], y_2[x2], y_2[x3], y_2[x4],
      keySto1_2, keySto2_2, keySto3_2, keySto4_2 );
    //Compare all key hypothesis of first and second ciphertexts
    //Get number of common key sets
    int keyNum = compareKeys(key, keySto1, keySto2, keySto3, keySto4, keySto1_2, keySto2_2, keySto3_2, keySto4_2);
    printf("Number of key found for (%2d,%2d,%2d,%2d): %d\n", x1, x2, x3, x4,keyNum);
    //Store it in the final key storage
    keyArray[x1] = key[0];
    keyArray[x2] = key[1];
    keyArray[x3] = key[2];
    keyArray[x4] = key[3];
    return keyNum;
}
//Takes two fault-free ciphertexts
//Return 1 if unique key is found
int step(mpz_t c, mpz_t c2){
  mpz_t cF; mpz_init(cF);
  mpz_t cF2; mpz_init(cF2);
  //induce a fault into a byte of the statematrix, which is the input to the eighth round
  char* fault =  faultSpec(8, 1, 0, 0, 0);

  //Find fault-free ciphertext for the first plaintext
  interact(cF, fault, pt);
  gmp_printf("i: %d , Ciphertext with fault : %ZX\n", interaction,  cF);
  //Find fault-free ciphertext for the second plaintext
  interact(cF2, fault, pt2);
  gmp_printf("i: %d , Ciphertext with fault : %ZX\n", interaction,  cF2);

  //Convert mpz_t into octet string
  char* ct = int2oct(c);
  char* ctF = int2oct(cF);
  char* ct2 = int2oct(c2);
  char* ctF2 = int2oct(cF2);
  //Convert into state matrix Array
  convertToIntArray(x, ct);
  convertToIntArray(y, ctF);
  convertToIntArray(x_2, ct2);
  convertToIntArray(y_2, ctF2);

  //Find keys by solving equations.
  //Check every function found only one solution
  int keyTest = 1;
  keyTest = keyTest & (findSolution(0, 7, 10, 13));
  keyTest = keyTest & (findSolution(11, 14, 1, 4));
  keyTest = keyTest & (findSolution(15, 8, 2, 5));
  keyTest = keyTest & (findSolution(9, 12, 3, 6));
//  keyTest = keyTest & (findSolution(11, 14, 1, 4));
//  keyTest = keyTest & (findSolution(2, 5, 15, 8));
//  keyTest = keyTest & (findSolution(9, 12, 3, 6));
  mpz_clear(cF);
  mpz_clear(cF2);

  return keyTest;
}

void attack() {
  mpz_t m;      mpz_init(m);
  mpz_t c;      mpz_init(c);
  mpz_t m2;      mpz_init(m2);
  mpz_t c2;      mpz_init(c2);

  oct2int(m, pt);
  oct2int(m2, pt2);

  //Get fault free ciphertexts
  interact(c, "", pt);
  gmp_printf("i: %d ,Fault free ciphertext : %ZX\n",interaction, c);
  interact(c2, "", pt2);
  gmp_printf("i: %d ,Fault free ciphertext : %ZX\n",interaction, c2);
  int keyNum=0;
  //Repeat operation until it finds the unique solution
  while(keyNum!=1){
    keyNum = step(c, c2);
  }
  printf("Target Material : ");
  for (int i = 0;i<OCTET;i++){
    if (keyArray[i]<OCTET) printf("0");
    printf("%X", keyArray[i]);
  }
  printf("\n");
  gmp_printf("Total Number of Interaction: %d\n", interaction);

  mpz_clear(m);
  mpz_clear(c);
  mpz_clear(m2);
  mpz_clear(c2);
}

void cleanup( int s ){
  // Close the   buffered communication handles.
  fclose( target_in  );
  fclose( target_out );

  // Close the unbuffered communication handles.
  close( target_raw[ 0 ] );
  close( target_raw[ 1 ] );
  close( attack_raw[ 0 ] );
  close( attack_raw[ 1 ] );

  // Forcibly terminate the attack target process.
  if( pid > 0 ) {
    kill( pid, SIGKILL );
  }
  // Forcibly terminate the attacker      process.
  exit( 1 );
}

/*
The main function
*/
int main( int argc, char* argv[] ) {
  // Ensure we clean-up correctly if Control-C (or similar) is signalled.
    signal( SIGINT, &cleanup );

    // Create pipes to/from attack target; if it fails the reason is stored
    // in errno, but we'll just abort.
    if( pipe( target_raw ) == -1 ) {
      abort();
    }
    if( pipe( attack_raw ) == -1 ) {
      abort();
    }

    switch( pid = fork() ) {
      case -1 : {
        // The fork failed; reason is stored in errno, but we'll just abort.
        abort();
      }
      case +0 : {
        // (Re)connect standard input and output to pipes.
        close( STDOUT_FILENO );
        if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
          abort();
        }
        close(  STDIN_FILENO );
        if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
          abort();
        }
        execl( argv[ 1 ], argv[ 0 ], NULL );
        // Break and clean-up once finished.
        break;
      }
      default : {
          // Construct handles to attack target standard input and output.
          if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
            abort();
          }
          if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
            abort();
          }

          // Execute a function representing the attacker.
          attack();

        // Break and clean-up once finished.
        break;
      }
    }

    // Clean up any resources we've hung on to.
    cleanup( SIGINT );
    return 0;
}
