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
char* pt ="3243F6A8885A308D313198A2E0370734";
char* pt2 = "00112233445566778899AABBCCDDEEFF";

int s[256] =
{
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
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
//inverse S-box
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
void interact(  mpz_t c, const char* spec, const mpz_t m){
  //Send spec and m
  gmp_fprintf(target_in, "%s\n", spec); fflush(target_in);
  gmp_fprintf(target_in, "%ZX\n", m); fflush(target_in);
  //Receive c from target
  if (gmp_fscanf(target_out, "%ZX", c) == 0) { abort(); }
  interaction++;
}

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet = NULL;
  int size = 32;
  //int size = mpz_sizeinbase(N, 16);
  int l = mpz_sizeinbase(i, 16);
  octet = malloc(size+1);

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

void compareKey(int* result, int iA, int iB, int* a, int* b){
  int index = 0;
  for (int i = 0;i<iA;i++){
    if (a[i]== -1) break;
    for (int j = 0;j<iB;j++){
        if (b[j]== -1) break;
        if (a[i] == b[j]) {
          result[index] = a[i];
          index++;
        }
    }
  }
  result[index]=-1;
}

int add(int a, int b){
  return a^b;
}
int mul(int a, int b){
  int p = 0;
  while(b){
    if (b & 1){
      p = p^a;
    }
    if (a & 0x80){
      a = (a<<1)^0x11b;
    }
    else {
      a <<=1;
    }
    b >>= 1;
  }
  return p;
}
int findKeyHypothesis(int* k1, int* k8, int* k11, int* k14, char* ct, char* ctF){
  //int k[16] = {0};
  int x[16] = {0};
  int y[16] = {0};
  char tmp[3];
  tmp[2] = '\0';
  for (int i = 0;i<strlen(ct);i=i+2){
    if (i==0){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[i]=(int) strtol(tmp, NULL, 16);
      tmp[0] = ctF[i];
      tmp[1] = ctF[i+1];
      y[i]=(int) strtol(tmp, NULL, 16);
    }
    else if (i==14){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[(i/2)]=(int)strtol(tmp, NULL, 16);
      tmp[0] = ctF[i];
      tmp[1] = ctF[i+1];
      y[(i/2)]=(int)strtol(tmp, NULL, 16);
    }
    else if (i==20){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[(i/2)]=(int)strtol(tmp, NULL, 16);
      tmp[0] = ctF[i];
      tmp[1] = ctF[i+1];
      y[(i/2)]=(int)strtol(tmp, NULL, 16);
    }
    else if (i==26){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      x[(i/2)]=(int)strtol(tmp, NULL, 16);
      tmp[0] = ctF[i];
      tmp[1] = ctF[i+1];
      y[(i/2)]=(int)strtol(tmp, NULL, 16);
    }
  }

  int deltaArray[256];
  int index = 0;
  int i = 0, j = 0, z = 0, l = 0, delta=1;
  //print state matrix for each ct row-wise order
  for(int w = 0;w<16;w++){
    printf("%x ", x[w]);
    if (w%4 == 3) printf("\n");
  }
  for(int w = 0;w<16;w++){
    printf("%x ", y[w]);
    if (w%4 == 3) printf("\n");
  }
  //guess k1 and k14
  /*
  x[0] =238;//13;// 238;
  x[7] = 59;//15;//59;
  x[10] =210; //165;//210;
  x[13] = 181;//113;//181;
  y[0] = 47; //92;//47;
  y[7] = 149;//27;//149;
  y[10] = 120;//251;//120;
  y[13] = 255;//161;//255;
  printf("test %d\n", inv_s[238^45]^inv_s[47^45]);
  printf("test %d\n", inv_s[59^234]^inv_s[149^234]);
  printf("test %d\n", inv_s[210^162]^inv_s[120^162]);
  printf("test %d\n", inv_s[181^65]^inv_s[255^65]);
  printf("test %d %d\n", mul(2, 224), mul(3, 224));*/
for (int i1 = 0;i1<256;i1++){
    for (int i14 = 0;i14<256;i14++){
      int lhs1 = inv_s[x[0]^i1]^inv_s[y[0]^i1];
      int rhs1 = inv_s[x[13]^i14]^inv_s[y[13]^i14];
      if (lhs1 == mul(2, rhs1)){
        for (int i11 = 0;i11<256;i11++){
          int rhs2 = inv_s[x[10]^i11]^inv_s[y[10]^i11];
          if (rhs1 == rhs2){
            for (int i8 = 0;i8<256;i8++){
              int lhs2 = inv_s[x[7]^i8]^inv_s[y[7]^i8];
              if (lhs2 == mul(3, rhs1)){
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
  return index;
}

//Reduce the overlapped key hypothesis
//ind: number of elements in k array
void reduceKeySpace(int ind, int* list, int* k){
  int index = 1;
  int flag = 0;
  list[0] = k[0];
  int i = 1;
  for(i = 1;i<ind;i++){
    flag = 0;
    for(int j = 0;j<(index);j++){
      if (k[i] == list[j]){
        flag =1;
        break;
      }
    }
    if (flag != 1){
      list[index] = k[i];
      index++;
    }
  }
  list[index] = -1;
}

void step1(mpz_t c, mpz_t m, mpz_t c2, mpz_t m2){
  mpz_t cF;
  mpz_init(cF);
  mpz_t cF2;
  mpz_init(cF2);
  //induce a fault into a byte of the statematrix, which is the input to the eighth round
  char* fault =  faultSpec(9, 1, 0, 0, 0);
  /*interact(cF, fault, m);
  gmp_printf("%s\n", fault);
  gmp_printf("1 S1: %ZX\n", cF);
  gmp_printf("1 S1: %ZX\n", c);
  fault = faultSpec(8, 0, 1, 0, 0);
  interact(cF, fault, m);
  gmp_printf("%s\n", fault);
  gmp_printf("2 S1: %ZX\n", cF);
  gmp_printf("2 S1: %ZX\n", c);
 fault = faultSpec(8, 3, 1, 0, 0);
interact(cF, fault, m);
gmp_printf("%s\n", fault);
gmp_printf("4 S1: %ZX\n", cF);
gmp_printf("4 S1: %ZX\n", c);*/
interact(cF, fault, m);
gmp_printf("4 S1: %ZX\n", c);
gmp_printf("4 S1: %ZX\n", cF);

  char* ct = int2oct(c);
  char* ctF = int2oct(cF);
  int k1[256]={0}, k8[256]={0}, k11[256]={0}, k14[256]={0};
  int index = findKeyHypothesis(k1, k8, k11, k14, ct, ctF);

  //for (int i = 0;i<index;i++){
  //  gmp_printf("index %d %d %d %d\n", k1[i], k8[i], k11[i], k14[i]);
  //}

  interact(cF2, fault, m2);
  gmp_printf("4 S1: %ZX\n", c2);
  gmp_printf("4 S1: %ZX\n", cF2);

  char* ct2 = int2oct(c2);
  char* ctF2 = int2oct(cF2);
  int k1_2[256]={0}, k8_2[256]={0}, k11_2[256]={0}, k14_2[256]={0};
  int index2 = findKeyHypothesis(k1_2, k8_2, k11_2, k14_2, ct2, ctF2);

  /*for (int i = 0;i<index2;i++){
    gmp_printf("index %d %d %d %d\n", k1_2[i], k8_2[i], k11_2[i], k14_2[i]);
  }*/
  int a[256], a1[256], a2[256], a3[256];
  int a4[256], a5[256], a6[256], a7[256];
  reduceKeySpace(index, a, k1);
  int i = 0;
  printf("k1  ");
  while(a[i]!=-1){
    printf("%3d ", a[i]); i++;
  }
  i = 0;
  printf("\nk8  ");
  reduceKeySpace(index, a1, k8);
  while(a1[i]!= -1){
    printf("%3d ", a1[i]); i++;
  }
  i = 0;
  printf("\nk11 ");
  reduceKeySpace(index, a2,  k11);
   while(a2[i]!=-1){
    printf("%3d ", a2[i]); i++;
  }
  i = 0;
  printf("\nk14 ");
  reduceKeySpace(index, a3,  k14);
    while(a3[i]!=-1){
    printf("%3d ", a3[i]); i++;
  }
  i = 0;
  printf("\nk1  ");
  reduceKeySpace(index2, a4,  k1_2);
      while(a4[i]!=-1){
    printf("%3d ", a4[i]); i++;
  }
  i = 0;
  printf("\nk8  ");
  reduceKeySpace(index2,a5,  k8_2);
      while(a5[i]!=-1){
    printf("%3d ", a5[i]); i++;
  }
  i = 0;
  printf("\nk11 ");
  reduceKeySpace(index2,a6,  k11_2);
      while(a6[i]!=-1){
    printf("%3d ", a6[i]); i++;
  }
  i = 0;
  printf("\nk14 ");
  reduceKeySpace(index2,a7,  k14_2);
  while(a7[i]!=-1){
    printf("%3d ", a7[i]); i++;
  }
  printf("\n");
  int result1[256];
  compareKey(result, 256, 256, a, a4);
  while(result1[i]!=-1){printf("%d ", result1[i]);i++;} i=0;printf("\n");
  int result2[256]={0};
  compareKey(result2, 256, 256, a1, a5);
  while(result2[i]!=-1){printf("%d ", result2[i]);i++;} i=0;printf("\n");
  int result3[256]={0};
  compareKey(result3, 256, 256, a2, a6);
  while(result3[i]!=-1){printf("%d ", result3[i]);i++;} i=0;printf("\n");
  int result4[256]={0};
  compareKey(result4, 256, 256, a3, a7);
  while(result4[i]!=-1){printf("%d ", result4[i]);i++;} i=0;printf("\n");
  mpz_clear(cF);
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
  //mpz_t cF;      mpz_init(cF);//with fault

  //Unused variables
  /*mpz_t N;      mpz_init(N);
  mpz_t e;      mpz_init(e);
  mpz_t cY;     mpz_init(cY);
  mpz_t cZ;     mpz_init(cZ);
  mpz_t dFinal; mpz_init(dFinal);//Final Target Material
  mpz_set_ui(dFinal, 1);
  mpz_t R;      mpz_init(R);        //For Montgomery reduction
  mpz_t N2;     mpz_init(N2);      //For Montgomery reduction
  mpz_t rInv;   mpz_init(rInv);  //For Montgomery reduction
  mpz_t cTmp;   mpz_init(cTmp);  //mtmp
  mpz_t cTmpC;  mpz_init(cTmpC);//mtmp * m
  mpz_t dTmp;   mpz_init(dTmp);
  int yAvg1, zAvg1, yAvg2, zAvg2; //time average for each ciphertext set
  int yNum1, zNum1, yNum2, zNum2; //number of ciphertexts in each set
  int tY, tZ;
  mpz_t mY;mpz_init(mY);
  mpz_t mZ;mpz_init(mZ);
  int cNum = 50;//number of ciphertexts in the set
  int endFlag = 0;
  int j = 1;    //bit number

*/
  oct2int(m, pt);
  oct2int(m2, pt2);
  //gmp_printf("TEST %ZX\n", test);
  //gmp_printf("TEST %Zd\n", test);

  //srand(time(NULL));

  //Get fault free ciphertexts
  interact(c, "", m);
  gmp_printf("i: %d ,Fault free ciphertext : %ZX\n",interaction, c);
  interact(c2, "", m2);
  gmp_printf("i: %d ,Fault free ciphertext : %ZX\n",interaction, c2);

  step1(c, m, c2, m2);

  //END
  gmp_printf("Target Material : %ZX\n", c);
  gmp_printf("Total Number of Interaction: %d\n", interaction);

  mpz_clear(m);
  mpz_clear(c);
//  mpz_clear(cF);
  /*mpz_clear(dTmp);
  mpz_clear(N);
  mpz_clear(e);
  mpz_clear(cY);
  mpz_clear(cZ);
  mpz_clear(dFinal);
  mpz_clear(R);
  mpz_clear(N2);
  mpz_clear(rInv);
  mpz_clear(cTmp);
  mpz_clear(cTmpC);*/
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
