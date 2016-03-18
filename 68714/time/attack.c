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

FILE* data_in  = NULL; //.conf file

int interaction= 0;
char N2[256];
char e2[256];
char lString[256];
char cString[256];

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet;

  int l = mpz_sizeinbase(i, 16);
  int size;
  if (l % 2 != 0) size = l+1;
  else size = l;

  octet = malloc(size+1);

  char* tmpStr = NULL;
  tmpStr = mpz_get_str(tmpStr, 16, i);

  octet[0] =toupper(tmpStr[size-2]);
  octet[1] =toupper(tmpStr[size-1]);

  for (int k = 2;k<size;k = k+2){
    octet[k] = toupper(tmpStr[size-k-2]);
    if ((size != l)&& (k == (size-2))) octet[k+1] = '0';
    else octet[k+1] = toupper(tmpStr[size-k-1]);
  }
  octet[size] = '\0';
  return octet;
}

//Convert octet string to integer
void oct2int(mpz_t i, const char* string){
  int size = strlen(string);
  mpz_set_ui(i, 0);
  mpz_t tmp;mpz_init(tmp);
  mpz_t tmp2;mpz_init(tmp2);
  mpz_t two;mpz_init(two);mpz_set_ui(two, 2);
  char octet[3] = {'\0'};
  for (int k = 0;k<size;k = k+2){
    octet[0] = string[k];
    octet[1] = string[k+1];
    mpz_set_str(tmp, octet, 16);
    mpz_pow_ui(tmp2, two, 4*k);
    mpz_mul(tmp, tmp, tmp2);
    mpz_add(i, i, tmp);
  }
  mpz_clear(tmp);
  mpz_clear(tmp2);
  mpz_clear(two);
}

void interact( int* t, mpz_t m, const mpz_t c){
  //Send c
  //fprintf( target_in, "%s\n", c );  fflush( target_in );
  gmp_fprintf(target_in, "%ZX\n", c); fflush(target_in);
  //Receive execution time and plaintext from target
  if ( 1 != fscanf(target_out, "%d", t)){
    abort();
  }
  if (gmp_fscanf(target_out, "%ZX", m) == 0) {
    abort();
  }
  interaction++;
}

void interact_R( int* t, mpz_t m, const mpz_t c, const mpz_t N, const mpz_t d){
  //Send c, N, d
  gmp_fprintf(R_in, "%ZX\n", c); fflush(R_in);
  gmp_fprintf(R_in, "%ZX\n", N); fflush(R_in);
  gmp_fprintf(R_in, "%ZX\n", d); fflush(R_in);
  //Receive execution time and plaintext from target
  if ( 1 != fscanf(R_out, "%d", t)){
    abort();
  }
  if (gmp_fscanf(R_out, "%ZX", m) == 0) {
    abort();
  }
  interaction++;
}

void find_R(mpz_t R, const mpz_t N){
  mpz_set_ui(R, 1);
  int length = mpz_sizeinbase(N, 2);//N bit size
  int lengthR = length%64;
  if (lengthR!= 0) length= length +(64 - lengthR)-1;
  mpz_mul_2exp(R, R, length);
}
//N * NR = -1 MOD R
void find_N2(mpz_t N2, const mpz_t N, const mpz_t R){
  mpz_t tmp; mpz_init(tmp);
  mpz_t a; mpz_init(a);
  mpz_t b; mpz_init(b);

  mpz_set_ui(N2, 0);// N2 = 0
  mpz_set_ui(a, 0); // a = 0
  mpz_set_ui(b, 1); // b = 1
  int l = mpz_sizeinbase (N, 2)/64 - 1; //l = binary size of N - 1

  while(l > 0){
    mpz_mod_ui(tmp, a, 2);
    if (mpz_cmp_ui(tmp, 0) == 0){//if (a&1)==0
      mpz_add(a, a, R);//a = a + N

      mpz_add(N2, N2, b);//N2 = N2 + b
    }
    mpz_div_2exp(a, a, 1);//a= a / 2
    mpz_mul_2exp(b, b, 1);//b= b * 2;
    l--;
  }
}


//mpz_t N, e, ...
void attack() {
  mpz_t N;mpz_init(N);
  mpz_t e;mpz_init(e);
  mpz_t m;mpz_init(m);
  mpz_t c;mpz_init(c);
  mpz_t d_R1; mpz_init(d_R1);
  mpz_t d_R0; mpz_init(d_R0);
  mpz_t d; mpz_init(d);
  mpz_t m_R;mpz_init(m_R);

  mpz_t Y;mpz_init(Y);
  mpz_t Z2;mpz_init(Z2);
  mpz_t Z3;mpz_init(Z3);
  mpz_t cY;mpz_init(cY);
  mpz_t cZ;mpz_init(cZ);
  mpz_t dFinal;mpz_init(dFinal);mpz_set_ui(dFinal, 1);

mpz_t R;mpz_init(R);
  mpz_t N2;mpz_init(N2);

  int r = 0;
  int r_R = 0;

  //Read N and e from conf file
  if (gmp_fscanf(data_in, "%ZX", N) == 0) {
    abort();
  }
  if (gmp_fscanf(data_in, "%ZX", e) == 0) {
    abort();
  }
  fclose(data_in);

  //Choose the set of ciphertexts
  mpz_set_ui(c, 12312901293102931);


  //Guess the size of the key
  /*int size = 1;
  mpz_set_ui(d_R1, 1);
  mpz_set_ui(d_R0, 1);
  r = 0;
  r_R = -1;
  int r_R0 = -1;
  while (r>=r_R){
    interact(&r, m, c);
    interact_R(&r_R, m_R, c, N, d_R1);
    interact_R(&r_R0, m_R, c, N, d_R0);
    printf("%d %d %d\n", r_R, r, r_R0);
    if (r<r_R) break;
    mpz_mul_ui(d_R1, d_R1, 2);
    mpz_mul_ui(d_R0, d_R0, 2);
    mpz_add_ui(d_R1, d_R1, 1);
    size++;
  }
  printf("size %d\n", size);
  int index = size - 1;
  mpz_set_ui(d_R1, 1);
  mpz_set_ui(d_R0, 1);
*/
  /*//Initial key hypothesis
  for (int i = size-1;i>=0;i--){
      mpz_mul_ui(d_R1, d_R1, 2);
      mpz_mul_ui(d_R0, d_R0, 2);
    //1 * 2^i
    if (i == size - 1) {
      mpz_add_ui(d_R1, d_R1, 1);
    }
  }*/

  //Find R for Montgomery reduction
  find_R(R, N);
  //Find N'
    mpz_t tmpN;mpz_init(tmpN);
  find_N2(N2, N, R);
  mpz_mul(tmpN, N2, N);
  mpz_mod(tmpN, tmpN, R);
  mpz_sub(tmpN, tmpN, R);
  gmp_printf("N' %Zd\n", tmpN);


  int yAvg, zAvg;//time average for each ciphertext set
  int emp = 200;//empirical value to determine the significant difference between y and z time
  int tY, tZ;
  mpz_t mY;mpz_init(mY);
  mpz_t mZ;mpz_init(mZ);
  int cNum = 10;//number of ciphertexts in the set
  int endFlag = 0;
  int dj = 0;//each bit value
  int j = 1;
  //Loop for finding entire key d1-n
  while(endFlag != 0)//change to until reach the last bit
  {
    //Range generation
    //Y^3< N
    if (mpz_root(Y, N, 3) != 0){
      mpz_sub_ui(Y, Y, 1);
    }

    //Z^2 < N < Z^3
    mpz_sqrt(Z2, N);
    if (mpz_root(Z3, N, 3) != 0){
      mpz_add_ui(Z3, Z3, 1);
    }
    //initiate average y and z
    yAvg = 0; zAvg = 0;
    //Loop for statistics
    for (int count = 0;count< cNum;count++){
      //Generate Y and Z ciphertext
      gmp_randstate_t state;//要改良
      gmp_randinit_mt(state);
      mpz_urandomm(cY, state, Y);
      mpz_set_ui(cZ, 0);
      while(mpz_cmp(cZ, Z3)<=0){
        gmp_randinit_mt(state);
        mpz_urandomm(cZ, state, Z2);
      }
      gmp_printf("%d %d %d\n%ZX\n%ZX\n", mpz_cmp(cY, Y), mpz_cmp(cZ, Z2), mpz_cmp(cZ, Z3), cY, cZ);
      //Should print negative, negative, positive


      tY = 0; tZ = 0;
      //Send Y to oracle
      interact(&tY, mY, cY);
      yAvg = yAvg + tZ;
      //Send Z to oracle
      interact(&tZ, mZ, cZ);
      zAvg = zAvg + tZ;
    }
    //Analysis: take average y and z, dj = 1? 0?
    yAvg = yAvg / cNum;
    zAvg = zAvg / cNum;
    printf("d bit: %d Avg Y time: %d\n", j, yAvg);
    printf("d bit: %d Avg Z time: %d\n", j, zAvg);
    if (zAvg > yAvg + emp) {
        mpz_mul_ui(dFinal, dFinal, 2);
        mpz_add_ui(dFinal, dFinal, 1);
    }
    else mpz_mul_ui(dFinal, dFinal, 2);
    //Update j index value?
    j++;
  }
/*while (endFlag != 1){
  //Send c, N and key hypothsis d,
  //Receive time taken and decrypted message
  interact_R(&r_R, m_R, c, N, d_R1);
  gmp_printf("Time : %d\n", r_R);
  gmp_printf("Ciphertext : %ZX\n", c);
  gmp_printf("Key Hypothesis : %ZX\n", d_R1);
  gmp_printf("Plaintext : %ZX\n", m_R);

  //Send c and receive time taken and decrypted message
  interact(&r, m, c);
  interaction++;
  gmp_printf("Time : %d\n", r);
  gmp_printf("Ciphertext : %ZX\n", c);
  gmp_printf("Plaintext : %ZX\n", m);

//TEST

  //Analysis
  //if index bit hypothesis is right...
  index--;
  //Update key hypothesis
  mpz_set_ui(tmp, 1);
  for (int i = index;i>=0;i--){
    mpz_mul_ui(tmp, tmp, 2);
  }
  mpz_set(d_R0, d_R1);
  mpz_add(d_R1, d_R1, tmp);
}*/

//END
gmp_printf("Target Material : %ZX\n", dFinal);
gmp_printf("Total Number of Interaction: %d\n", interaction);

mpz_clear(N);
mpz_clear(e);
mpz_clear(m);
mpz_clear(c);
mpz_clear(d_R1);
mpz_clear(d_R0);
mpz_clear(d);
mpz_clear(m_R);
mpz_clear(Y);
mpz_clear(Z2);
mpz_clear(Z3);
mpz_clear(cY);
mpz_clear(cZ);
mpz_clear(dFinal);

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

void cleanupR( int s ){
  // Close the   buffered communication handles.
  fclose( R_in  );
  fclose( R_out );
  // Close the unbuffered communication handles.
  close( target_R_raw[ 0 ] );
  close( target_R_raw[ 1 ] );
  close( attack_R_raw[ 0 ] );
  close( attack_R_raw[ 1 ] );

  // Forcibly terminate the attack target process.
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
          if ((data_in = fopen(argv[2], "r"))== NULL){
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
