#include "attack.h"
#include "math.h"
#include "time.h"
#include "limits.h"
#include "ctype.h"

#define BUFFER_SIZE ( 80 )

pid_t pid        = 0;    // process ID (of either parent or child) from fork
pid_t pid_R        = 0;    // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker
int   target_R_raw[ 2 ];   // unbuffered communication: attacker -> R
int   attack_R_raw[ 2 ];   // unbuffered communication: R -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream
FILE* R_out = NULL; // buffered attack R input  stream
FILE* R_in  = NULL; // buffered attack R output stream

int interaction= 0;

void interact( char* p, mpz_t c, const mpz_t m){
  //Send c
  gmp_fprintf(target_in, "%ZX\n",m); fflush(target_in);
  //Receive execution time and plaintext from target
  if ( gmp_fscanf(target_out, "%s", p) == 0) { abort(); }
  if (gmp_fscanf(target_out, "%ZX", c) == 0) { abort(); }
  interaction++;
}
//call by seprateTrace(&v, consumption, trace)
void separateTrace(int* l, int* consumption, char* trace){
int i = 0;
//get length
  while(trace[i]!='\0'){
    if (trace[i]==','){
      char sub[5];
      for(int j = 0;j<i;j++){
        sub[j] = trace[j];
      }
      l = strtol(sub, NULL, 10);
      break;
    }
    i++;
  }
  consumption = malloc(sizeof(int)*l);
  char subStr[3];
  int index = 0;
  int indexC = 0;
  int k  = 0;
  while(trace[k]!='\0'){
    if (k<i) {k++;continue;}
    if (trace[k]==','){
      consumption[indexC]= strtol(subStr, NULL, 10);
      gmp_printf("Check consumption: %d\n", consumption[indexC]);
      memset(subStr, 0, sizeof(subStr));
      indexC++;
      index = 0;
      gmp_printf("Check subStr is empty: %s\n", subStr);
    }
    else{
      subStr[index] = trace[k];
      gmp_printf("Check subStr: %s\n", subStr);
      index++;
    }
    k++;
  }
}

void interact_R( char* p, mpz_t c, const mpz_t m, const mpz_t k){
  //Send c, N, d
  gmp_fprintf(R_in, "%ZX\n", m); fflush(R_in);
  gmp_fprintf(R_in, "%ZX\n", k); fflush(R_in);
  //Receive execution time and plaintext from target
  if ( gmp_fscanf(R_out, "%s", p) == 0) { abort(); }
  if (gmp_fscanf(R_out, "%ZX", c) == 0) { abort(); }
  interaction++;
}

//mpz_t N, e, ...
void attack() {
  mpz_t N;      mpz_init(N);
  mpz_t e;      mpz_init(e);
  mpz_t m;      mpz_init(m);
  mpz_t c;      mpz_init(c);
  mpz_t m_R;    mpz_init(m_R);
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
  int r_R = 0;

srand(time(NULL));
  //Loop for finding entire key d1-n
/*  while(endFlag != 1)//change to until reach the last bit
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
  }*/
  //END
  gmp_printf("Target Material : %ZX\n", dFinal);
  gmp_printf("Total Number of Interaction: %d\n", interaction);
  /*mpz_clear(dTmp);
  mpz_clear(N);
  mpz_clear(e);
  mpz_clear(m);
  mpz_clear(c);
  mpz_clear(m_R);
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
  fclose( R_in  );
  fclose( R_out );
  // Close the unbuffered communication handles.
  close( target_raw[ 0 ] );
  close( target_raw[ 1 ] );
  close( attack_raw[ 0 ] );
  close( attack_raw[ 1 ] );
  close( target_R_raw[ 0 ] );
  close( target_R_raw[ 1 ] );
  close( attack_R_raw[ 0 ] );
  close( attack_R_raw[ 1 ] );
  // Forcibly terminate the attack target process.
  if( pid > 0 ) {
    kill( pid, SIGKILL );
  }
  if( pid_R > 0 ) {
    kill( pid_R, SIGKILL );
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
        if( pipe( target_R_raw ) == -1 ) {
          abort();
        }
        if( pipe( attack_R_raw ) == -1 ) {
          abort();
        }

        switch(pid_R = fork()){
          case -1 : {
            // The fork failed; reason is stored in errno, but we'll just abort.
            abort();
          }

          case +0 : {
            // (Re)connect standard input and output to pipes.
            close( STDOUT_FILENO );
            close(  STDIN_FILENO );
            if( dup2( attack_R_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
              abort();
            }

            if( dup2( target_R_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
              abort();
            }
            // Produce a sub-process representing the attack target.
            execl( "68714.R", argv[ 0 ], NULL );

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
          if( ( R_out = fdopen( attack_R_raw[ 0 ], "r" ) ) == NULL ) {
            abort();
          }
          if( ( R_in  = fdopen( target_R_raw[ 1 ], "w" ) ) == NULL ) {
            abort();
          }
          // Execute a function representing the attacker.
          attack();

          // Break and clean-up once finished.
          break;
        }
        // Break and clean-up once finished.
        break;
      }
      }
    }

    // Clean up any resources we've hung on to.
    cleanup( SIGINT );
    return 0;
}
