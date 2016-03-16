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


FILE* data_in  = NULL; //


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
}

void interact_R( int* t, mpz_t m, const mpz_t c, const mpz_t N, const mpz_t d){
  //Send c
  //fprintf( target_in, "%s\n", c );  fflush( target_in );
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


  mpz_t f2; mpz_init(f2);
  mpz_t f3;mpz_init(f3);
  mpz_t mmin;mpz_init(mmin);mpz_set_ui(mmin, 0);
  mpz_t mmax;mpz_init(mmax);mpz_set_ui(mmin, 1);
  mpz_t ftmp; mpz_init(ftmp);

  mpz_t send; mpz_init(send);
  mpz_t tmp;mpz_init(tmp);
  mpz_t tmp2;mpz_init(tmp2);

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
  gmp_printf("%ZX\n", N);
  //Choose the set of ciphertexts
  mpz_set_ui(c, 12312901293102931);

  //Guess one bit of the key
  int size = 1;//size = size of d ???
  mpz_set_ui(d_R1, 1);
  r = 0;
  r_R = -1;
  while (r>=r_R){
    interact_R(&r_R, m_R, c, N, d_R1);
    interact(&r, m, c);
    printf("%d %d\n", r_R, r);
    if (r<r_R) break;
    mpz_mul_ui(d_R1, d_R1, 2);
    mpz_add_ui(d_R1, d_R1, 1);
    size++;
  }
  int index = size - 1;
  mpz_set_ui(d_R1, 1);
  mpz_set_ui(d_R0, 1);

  //Initial key hypothesis
  for (int i = size-1;i>=0;i--){
      mpz_mul_ui(d_R1, d_R1, 2);
      mpz_mul_ui(d_R0, d_R0, 2);
    //1 * 2^i
    if (i == size - 1) {
      mpz_add_ui(d_R1, d_R1, 1);
    }
  }

  //INSERT LOOP HERE TO TEST KEY HYPO
  //This should be the last of the loop...?
  mpz_set_ui(tmp, 1);
  for (int i = index;i>=0;i--){
    mpz_mul_ui(tmp, tmp, 2);
  }
  mpz_set(d_R0, d_R1);
  mpz_add(d_R1, d_R1, tmp);

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


  //Analysis

//if index bit hypothesis is right...
index--;

gmp_printf("Target Material : %ZX\n", m);
gmp_printf("Total Number of Interaction: %d\n", interaction);

mpz_clear(N);
mpz_clear(e);
mpz_clear(m);
mpz_clear(c);
mpz_clear(d_R1);
mpz_clear(d_R0);
mpz_clear(d);
mpz_clear(m_R);
mpz_clear(f2);
mpz_clear(f3);
mpz_clear(mmin);
mpz_clear(mmax);
mpz_clear(ftmp);

mpz_clear(send);
mpz_clear(tmp);
mpz_clear(tmp2);
}
void cleanup( int s ){
  // Close the   buffered communication handles.
  fclose( target_in  );
  fclose( target_out );

//  fclose( R_in  );
//  fclose( R_out );
  // Close the unbuffered communication handles.
  close( target_raw[ 0 ] );
  close( target_raw[ 1 ] );
  close( attack_raw[ 0 ] );
  close( attack_raw[ 1 ] );

/*  close( target_R_raw[ 1 ] );
  close( attack_R_raw[ 0 ] );
  close( attack_R_raw[ 1 ] );
*/

  // Forcibly terminate the attack target process.
  if( pid > 0 ) {
    kill( pid, SIGKILL );
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
    signal( SIGINT, &cleanupR );

    // Create pipes to/from attack target; if it fails the reason is stored
    // in errno, but we'll just abort.
    if( pipe( target_raw ) == -1 ) {
      abort();
    }
    if( pipe( attack_raw ) == -1 ) {
      abort();
    }

    //printf("test1 %s\n", argv[1]);
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
        //printf("test2 %s\n", argv[1]);
        // Break and clean-up once finished.
        break;
      }

      default : {
      //printf("test3 %s\n", argv[1]);
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
            close( attack_R_raw[ 1 ] );
            close(  target_R_raw[ 0 ] );
            /*if( dup2( attack_R_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
              abort();
            }

            if( dup2( target_R_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
              abort();
            }*/
            //printf("test4 %s\n", argv[1]);

            // Produce a sub-process representing the attack target.
            execl( "68714.R", argv[ 0 ], NULL );

            // Break and clean-up once finished.
            break;
          }

        default : {
          //printf("test5 %s\n", argv[1]);
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
          //printf("test6 %s\n", argv[1]);

          attack();

          // Break and clean-up once finished.
          break;
        }
        // Execute a function representing the attacker.
//        attack();

        // Break and clean-up once finished.
        break;
      }
      }
    }

    // Clean up any resources we've hung on to.
    cleanupR( SIGINT );
    cleanup( SIGINT );
    return 0;
}
