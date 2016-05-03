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

int interaction= 0;
//saple plaintext
char* pt  = "3243F6A8885A308D313198A2E0370734";
char* pt2 = "00112233445566778899AABBCCDDEEFF";

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
  gmp_printf("test3\n");
  interaction++;
}

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet = NULL;
  int size = 32;
  //int size = mpz_sizeinbase(N, 16);
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
  for (int i = 0;i<256;i++){
    if (a1[i]== -1 || a2[i]== -1 || a3[i]== -1 || a4[i]== -1 ) break;
    for (int j = 0;j<256;j++){
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

void findK1(int c1, int c2, int c3, int c4,
    int cf1, int cf2, int cf3, int cf4,
      int* k1, int* k2, int* k3, int*k4){
  int index = 0;
  //guess k1 and k14
  for (int i1 = 0;i1<256;i1++){
    for (int i4 = 0;i4<256;i4++){
      int lhs1 = inv_s[c1^i1]^inv_s[cf1^i1];
      int rhs1 = inv_s[c4^i4]^inv_s[cf4^i4];
      if (lhs1 == polymul(2, rhs1)){
        //guess k11
        for (int i3 = 0;i3<256;i3++){
          int rhs2 = inv_s[c3^i3]^inv_s[cf3^i3];
          if (rhs1 == rhs2){
            //guess k8
            for (int i2 = 0;i2<256;i2++){
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
    k1[index] = -1;
    k2[index] = -1;
    k3[index] = -1;
    k4[index] = -1;
  //return index;
}


void convertToIntArray(int* x, char* ct){
  char tmp[3];
  tmp[2] = '\0';
  //Store ciphertexts into array
  for (int i = 0;i<strlen(ct);i=i+2){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[(i/2)]=(int)strtol(tmp, NULL, 16);
  }
}
//Find all possible key hypothesis and store them in 4 arrays.
//ct: fault free ciphertext in string
//ctF: faulty ciphertext in string
void findKeyHypothesis(int* k1, int* k2, int* k3, int* k4,
                      int* k5, int* k6, int* k7, int* k8,
                      int* k9, int* k10, int* k11, int* k12,
                      int* k13, int* k14, int* k15, int* k16,
                      char* ct, char* ctF){
  int x[16] = {0};
  int y[16] = {0};
/*
  char tmp[3];
  tmp[2] = '\0';
  //Store ciphertexts into array
  for (int i = 0;i<strlen(ct);i=i+2){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[(i/2)]=(int)strtol(tmp, NULL, 16);
      tmp[0] = ctF[i];
      tmp[1] = ctF[i+1];
      y[(i/2)]=(int)strtol(tmp, NULL, 16);
  }*/
  convertToIntArray(x, ct);
  convertToIntArray(y, ctF);

  findK1(x[0], x[7], x[10], x[13],
          y[0], y[7], y[10], y[13],
          k1, k8, k11, k14 );
          /*first = 2* last
          third = last
          second = 3* last*/
  findK1(x[4], x[1], x[14], x[11],
          y[4], y[1], y[14], y[11],
          k5, k2, k15, k12);

  findK1(x[11], x[14], x[4], x[1],
          y[11], y[14], y[4], y[1],
          k12, k15, k5, k2);
  findK1(x[2], x[5], x[15], x[8],
          y[2], y[5], y[15], y[8],
          k3, k6, k16, k9);
   findK1(x[9], x[12], x[3], x[6],
          y[9], y[12], y[3], y[6],
          k10, k13, k4, k7);

  /*int index = 0;
  //guess k1 and k14
  for (int i1 = 0;i1<256;i1++){
    for (int i14 = 0;i14<256;i14++){
      int lhs1 = inv_s[x[0]^i1]^inv_s[y[0]^i1];
      int rhs1 = inv_s[x[13]^i14]^inv_s[y[13]^i14];
      if (lhs1 == polymul(2, rhs1)){
        //guess k11
        for (int i11 = 0;i11<256;i11++){
          int rhs2 = inv_s[x[10]^i11]^inv_s[y[10]^i11];
          if (rhs1 == rhs2){
            //guess k8
            for (int i8 = 0;i8<256;i8++){
              int lhs2 = inv_s[x[7]^i8]^inv_s[y[7]^i8];
              //if all three equations are satisfied...
              if (lhs2 == polymul(3, rhs1)){
                k1[index] = i1;
                k8[index] = i8;
                k11[index] = i11;
                k14[index] = i14;
                index++;
              }
            }
          }
        }
      }
    }
  }
    k1[index] = -1;
    k8[index] = -1;
    k11[index] = -1;
    k14[index] = -1;
  //return index;*/
}
//Return 1 if unique key is found
int step1(mpz_t c, mpz_t c2, int* keyArray){
  mpz_t cF; mpz_init(cF);
  mpz_t cF2; mpz_init(cF2);

  //induce a fault into a byte of the statematrix, which is the input to the eighth round
  char* fault =  faultSpec(8, 1, 0, 0, 0);
  interact(cF, fault, pt);
  gmp_printf("4 S1: %ZX\n", c);
  gmp_printf("4 S1: %ZX\n", cF);

  char* ct = int2oct(c);
  char* ctF = int2oct(cF);
  int k1[256]={0}, k5[256]={0}, k9[256]={0}, k13[256]={0};
  int k2[256]={0}, k6[256]={0}, k10[256]={0}, k14[256]={0};
  int k3[256]={0}, k7[256]={0}, k11[256]={0}, k15[256]={0};
  int k4[256]={0}, k8[256]={0}, k12[256]={0}, k16[256]={0};
  int x[16]={0};
  int y[16]={0};
  convertToIntArray(x, ct);
  convertToIntArray(y, ctF);


  findK1(x[0], x[7], x[10], x[13], y[0], y[7], y[10], y[13], k1, k8, k11, k14 );
  findK1(x[1], x[4], x[14], x[11], y[1], y[4], y[14], y[11], k2, k5, k15, k12);
  findK1(x[2], x[5], x[15], x[8],y[2], y[5], y[15], y[8],  k3, k6, k16, k9);
  findK1(x[9], x[12], x[3], x[6],  y[9], y[12], y[3], y[6],  k10, k13, k4, k7);
/*
  findK1(x[11], x[14], x[4], x[1], y[11], y[14], y[4], y[1], k12, k15, k5, k2);
  findK1(x[2], x[5], x[15], x[8],y[2], y[5], y[15], y[8],  k3, k6, k16, k9);
  findK1(x[9], x[12], x[3], x[6],  y[9], y[12], y[3], y[6],  k10, k13, k4, k7);
*/
  /*for (int i = 0;i<index;i++){
    gmp_printf("index %d %d %d %d\n", k1[i], k8[i], k11[i], k14[i]);
  }*/
  printf("First analysis end\n");
  interact(cF2, fault, pt2);
  gmp_printf("4 S1: %ZX\n", c2);
  gmp_printf("4 S1: %ZX\n", cF2);

  char* ct2 = int2oct(c2);
  char* ctF2 = int2oct(cF2);

  int k1_2[256]={0}, k5_2[256]={0}, k9_2[256]={0}, k13_2[256]={0};
  int k2_2[256]={0}, k6_2[256]={0}, k10_2[256]={0}, k14_2[256]={0};
  int k3_2[256]={0}, k7_2[256]={0}, k11_2[256]={0}, k15_2[256]={0};
  int k4_2[256]={0}, k8_2[256]={0}, k12_2[256]={0}, k16_2[256]={0};
  convertToIntArray(x, ct2);
  convertToIntArray(y, ctF2);
  findK1(x[0], x[7], x[10], x[13], y[0], y[7], y[10], y[13], k1_2, k8_2, k11_2, k14_2 );
  findK1(x[1], x[4], x[14], x[11], y[1], y[4], y[14], y[11], k2_2, k5_2, k15_2, k12_2);
  findK1(x[2], x[5], x[15], x[8], y[2], y[5], y[15], y[8], k3_2, k6_2, k16_2, k9_2);
  findK1(x[9], x[12], x[3], x[6], y[9], y[12], y[3], y[6], k10_2, k13_2, k4_2, k7_2);
  /*for (int i = 0;i<index2;i++){
    gmp_printf("index %d %d %d %d\n", k1_2[i], k8_2[i], k11_2[i], k14_2[i]);
  }*/
  int key[4]={0};
  int test = 0;
  int test1 = compareKeys(key, k1, k8, k11, k14, k1_2, k8_2, k11_2, k14_2);
  printf("keys %d\n", test1);
int test0 = test1;
  keyArray[0] = key[0];
  keyArray[7] = key[1];
  keyArray[10] = key[2];
  keyArray[13] = key[3];
  test1 = compareKeys(key, k2, k5, k12, k15, k2_2, k5_2, k12_2, k15_2);
  printf("keys %d\n", test1);
  test = (test & test1);
  keyArray[1] = key[0];
  keyArray[4] = key[1];
  keyArray[11] = key[2];
  keyArray[14] = key[3];
  test1 = compareKeys(key, k3, k6, k9, k16, k3_2, k6_2, k9_2, k16_2);
  printf("keys %d\n", test1);
  test = (test & test1);
  keyArray[2] = key[0];
  keyArray[5] = key[1];
  keyArray[8] = key[2];
  keyArray[15] = key[3];
  test1 = compareKeys(key, k4, k7, k10, k13, k4_2, k7_2, k10_2, k13_2);
  printf("keys %d\n", test1);
  test = (test & test1);
  keyArray[3] = key[0];
  keyArray[6] = key[1];
  keyArray[9] = key[2];
  keyArray[12] = key[3];
  mpz_clear(cF);
  mpz_clear(cF2);

//  return (test0 & test1 & test2 & test3);
return test0;
}

//mpz_t N, e, ...
//r = {0-10} the round in which the fault occurs, #
//f = {0-3} 0 = addround, 1=subbytes, 2=shiftrows, 3=mixcolumns
//p = 0 fault before the round function, 1 after
//i, j  = row and column of state matrix fault occurs
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
  int keyArray[16]={0};
  while(keyNum!=1){
    keyNum = step1(c, c2, keyArray);
  }

  //END
  printf("Target Material : ");
  for (int i = 0;i<16;i++){
    if (keyArray[i]<16) printf("0");
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
