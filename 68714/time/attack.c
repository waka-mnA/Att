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

void interact( int* t, mpz_t m, const char* c){
  //Send c
  fprintf( target_in, "%s\n", c );  fflush( target_in );

  //Receive execution time and plaintext from target
  if ( 1 != fscanf(target_out, "%d", t)){
    abort();
  }
  if (gmp_fscanf(target_out, "%ZX", m) == 0) {
    abort();
  }
}

//mpz_t N, e, ...
void attack() {
  mpz_t N;mpz_init(N);
  mpz_t e;mpz_init(e);
  mpz_t m;mpz_init(m);
  mpz_t c;mpz_init(c);

  mpz_t B; mpz_init(B);
  mpz_t f1; mpz_init(f1);
  mpz_t f2; mpz_init(f2);
  mpz_t in;mpz_init(in);
  mpz_t f3;mpz_init(f3);
  mpz_t mmin;mpz_init(mmin);mpz_set_ui(mmin, 0);
  mpz_t mmax;mpz_init(mmax);mpz_set_ui(mmin, 1);
  mpz_t ftmp; mpz_init(ftmp);

  mpz_t send; mpz_init(send);
  mpz_t tmp;mpz_init(tmp);
  mpz_t tmp2;mpz_init(tmp2);

  int r = 0;

  if (gmp_fscanf(data_in, "%ZX", N) == 0) {
    abort();
  }
  if (gmp_fscanf(data_in, "%ZX", e) == 0) {
    abort();
  }

  fclose(data_in);

  interact(&r, m, c);
  interaction++;
gmp_printf("Time : %d\n", r);
gmp_printf("Target Material : %ZX\n", m);
gmp_printf("Total Number of Interaction: %d\n", interaction);

mpz_clear(N);
mpz_clear(e);
mpz_clear(m);
mpz_clear(c);
mpz_clear(B);
mpz_clear(f1);
mpz_clear(f2);
mpz_clear(in);
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

        // Produce a sub-process representing the attack target.
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

        if ((data_in = fopen(argv[2], "r"))== NULL){
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
