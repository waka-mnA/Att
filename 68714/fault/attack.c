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

void compareKeys(int index, int index2, int* correct, int* k1, int* k2, int* k3, int* k4, int* l1, int* l2, int* l3, int* l4){
  for(int i = 0;i<index;i++){
    for(int j = 0;j<index2;j++){
    if (k1[i] != l1[j]) continue;
    if (k2[i] != l2[j]) continue;
    if (k3[i] != l3[j]) continue;
    if (k4[i] != l4[j]) continue;
    correct[0] = k1[i];
    correct[1] = k2[i];
    correct[2] = k3[i];
    correct[3] = k4[i];
    gmp_printf("compare %d %d %d %d\n", correct[0], correct[1], correct[2], correct[3]);
    return;
  }
}
}
int findKeyHypothesis(int* k1, int* k8, int* k11, int* k14, char* ct, char* ctF){
  int k[16] = {0};
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
  //gmp_printf("%d %d %d %d\n", x[0], x[10], x[7], x[13]);
  //gmp_printf("%d %d %d %d\n",y[0], y[10], y[7], y[13]);
  int solved = 0;
  int deltaArray[256];
  int index = 0;
  int i = 0, j = 0, z = 0, l = 0, delta=1;
  while(solved == 0 && delta < 256/3){
    i=0;
    while(i<256){
      int delta1 =inv_s[x[0]^i]^inv_s[y[0]^i];
      j=0;
      while((delta1 == delta*2)&& j<256){
        int delta11 = inv_s[x[10]^j]^inv_s[y[10]^j];
        z=0;
          while((delta11 == delta)&& z<256){
            int delta14 = inv_s[x[13]^z]^inv_s[y[13]^z];
            l=0;
              while((delta14 == delta)&& l<256){
                int delta8 = inv_s[x[7]^l]^inv_s[y[7]^l];
                if (delta8 == delta*3){
                  k1[index] = i;
                  k8[index] = l;
                  k11[index]= j;
                  k14[index] = z;
                  deltaArray[index]= delta;
                  index++;
                }
                l++;
              }
            z++;
        }
        j++;
      }
      i++;
    }
    delta++;
  }


  return index;
}
void step1(mpz_t c, mpz_t m, mpz_t c2, mpz_t m2){
  mpz_t cF;
  mpz_init(cF);
  mpz_t cF2;
  mpz_init(cF2);
  //induce a fault into a byte of the statematrix, which is the input to the eighth round
  char* fault = faultSpec(8, 0, 0, 0, 0);
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
fault = faultSpec(9, 1, 0, 0, 0);
interact(cF, fault, m);
//gmp_printf("%s\n", fault);
gmp_printf("4 S1: %ZX\n", cF);
gmp_printf("4 S1: %ZX\n", c);

  char* ct = int2oct(c);
  char* ctF = int2oct(cF);
  int k1[256], k8[256], k11[256], k14[256];
  int index = findKeyHypothesis(k1, k8, k11, k14, ct, ctF);

  for (int i = 0;i<index;i++){
    gmp_printf("index %d %d %d %d\n", k1[i], k8[i], k11[i], k14[i]);
  }
  interact(cF2, fault, m2);
//  gmp_printf("%s\n", fault);
  gmp_printf("4 S1: %ZX\n", cF2);
  gmp_printf("4 S1: %ZX\n", c2);

    char* ct2 = int2oct(c2);
    char* ctF2 = int2oct(cF2);
    int k1_2[256], k8_2[256], k11_2[256], k14_2[256];
    int index2 = findKeyHypothesis(k1_2, k8_2, k11_2, k14_2, ct2, ctF2);

    for (int i = 0;i<index;i++){
      gmp_printf("index %d %d %d %d\n", k1_2[i], k8_2[i], k11_2[i], k14_2[i]);
    }
  /*for (int i = 0;i<index;i++){
    gmp_printf("index %d %d %d %d %d\n", deltaArray[i], k1[i], k8[i], k11[i], k14[i]);
  }*/
  int correctKeys[4] = {0};
  compareKeys(index, index2, correctKeys, k1, k8, k11, k14, k1_2, k8_2, k11_2, k14_2);

  gmp_printf("%d %d %d %d\n", correctKeys[0], correctKeys[1], correctKeys[2], correctKeys[3]);
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
    //Loop for finding entire key d1-n
  /*while(endFlag != 1)//change to until reach the last bit
  {
    //initiate average time
    yAvg1 = 0; zAvg1 = 0;
    yAvg2 = 0; zAvg2 = 0;
    yNum1 = 0; zNum1 = 0;
    yNum2 = 0; zNum2 = 0;
    int o1_flag = 0, o2_flag = 0;
    //Loop for statistics
    while(!((yNum1 >cNum) &&(yNum2 > cNum) && (zNum1>cNum)&&(zNum2>cNum))){
      //Choose random C
      int random = rand();
      gmp_randstate_t state;
      gmp_randinit_default(state);
      gmp_randseed_ui(state, random);
      mpz_urandomm(c, state, N);
      gmp_randclear(state);

      //get Ctmp = (c^j)^2
      interact_R(&r_R, cTmp, c, N, dFinal);
      mpz_mul(cTmp, cTmp, cTmp);
      mpz_mul(cTmpC, cTmp, c);

      //Check whether it will go through reduction
      //dj = 1, (Ctmp * C)^2
      if (monPro(cTmpC, cTmpC, N, N2, R)) {  o1_flag = 1; }
      else { o1_flag = 0; }
      //dj = 0, (Ctmp)^2
      if (monPro(cTmp, cTmp, N, N2, R)){  o2_flag = 1; }
      else { o2_flag = 0; }
      mpz_set(cY, c);
      mpz_set(cZ, c);

      //Send Y and Z to oracle
      interact(&tY, mY, cY);
      interact(&tZ, mZ, cZ);

      if (o1_flag == 1) {
        yNum1++;
        yAvg1 += tY;
      } else {
        yNum2++;
        yAvg2 += tY;
      }
      if (o2_flag == 1) {
        zNum1++;
        zAvg1 += tZ;
      } else {
        zNum2++;
        zAvg2 += tZ;
      }
    }
    //Analysis: take average y1, y2, z1 and z2, dj = 1? 0?
    yAvg1 = yAvg1 / yNum1;  //dj = 1, with reduction
    yAvg2 = yAvg2 / yNum2;  //dj = 1, without reduction
    zAvg1 = zAvg1 / zNum1;  //dj = 0, with reduction
    zAvg2 = zAvg2 / zNum2;  //dj = 0, without reduction
    printf("d bit: %d\nAvg (dj = 1) time difference: %d\n", j, yAvg1 - yAvg2);
    printf("Avg (dj = 0) time difference: %d\n",zAvg1-zAvg2);
    if ((yAvg1 - yAvg2) > (zAvg1 - zAvg2)) {
        mpz_mul_ui(dFinal, dFinal, 2);
        mpz_add_ui(dFinal, dFinal, 1);
        dChar[j] = '1';
    }
    else {
      mpz_mul_ui(dFinal, dFinal, 2);
        dChar[j] = '0';
    }
    dChar[j+1] = '\0';
    //Update j index value
    j++;
    //Print hexadecimal and binary key
    gmp_printf("d_x: %ZX\nd_b: %s\n", dFinal, dChar);

    //Guess the last bit
    //Test with last bit = 0
    mpz_mul_ui(dTmp, dFinal, 2);
    interact_R(&r_R, m_R, c, N, dTmp);
    interact(&tY, m, c);
    if (mpz_cmp(m_R, m) == 0) {
      endFlag = 1;
      mpz_mul_ui(dFinal, dFinal, 2);
    }
    //Test with last bit = 1
    mpz_add_ui(dTmp, dTmp, 1);
    interact_R(&r_R, m_R, c, N, dTmp);
    if (mpz_cmp(m_R, m) == 0) {
      endFlag = 1;
      mpz_mul_ui(dFinal, dFinal, 2);
      mpz_add_ui(dFinal, dFinal, 1);
    }

    if (j == 1023) endFlag = 1;
  }
  */
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
