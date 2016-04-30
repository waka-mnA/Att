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

//Function to generate fault specification
char* faultSpec( const int r, const int f, const int p, const int i, const int j){
  int size = 9;
  if (r > 9) size++;
  char* result= malloc(sizeof(char)*size);
  char sub[7];
  if (r > 9) {
    result[0]='1';
    result[1]='0';
    result[2]='\0';
  }
  else{
    result[0] = r+'0';
    result[1]='\0';
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
char* int2oct(const mpz_t i, const mpz_t N){
  char* octet = NULL;
  int size = mpz_sizeinbase(N, 16);
  int l = mpz_sizeinbase(i, 16);
  octet = malloc(size+1);

  char* tmpStr = NULL;
  tmpStr = mpz_get_str(tmpStr, 16, i);
  int index = 0;
  for (index = 0; index<=(size - l) ;index++){
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

void step1(mpz_t c, mpz_t m){
  mpz_t cF;
  mpz_init(cF);
  //induce a fault into a byte of the statematrix, which is the input to the eighth round
  char* fault = faultSpec(8, 1, 0, 0, 0);
  interact(cF, fault, m);
  gmp_printf("%s\n", fault);
  gmp_printf("S1: %ZX\n", cF);
  gmp_printf("S1: %ZX\n", c);
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
  mpz_t cF;      mpz_init(cF);//with fault

  //Unused variables
  mpz_t N;      mpz_init(N);
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


  oct2int(m, pt);
  //gmp_printf("TEST %ZX\n", test);
  //gmp_printf("TEST %Zd\n", test);

  //srand(time(NULL));

  //Get fault free ciphertexts
  interact(c, "", m);
  gmp_printf("i: %d ,Fault free ciphertext : %ZX\n",interaction, c);

  step1(c, m);
/*  //Loop for finding entire key d1-n
  while(endFlag != 1)//change to until reach the last bit
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
  mpz_clear(cF);
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
