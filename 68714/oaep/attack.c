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


void exp_mpz(mpz_t r, const mpz_t x, const mpz_t y){
  mpz_t n; mpz_init(n);
  mpz_t modTmp; mpz_init(modTmp);
  mpz_t y2; mpz_init(y2);

  mpz_set(y2, y);
  mpz_set_ui(n, 1);
  mpz_set(r, x);
  if (mpz_cmp_ui(y, 0) == 0) {
    mpz_set_ui(r, 1);
    return;
  }
  while(mpz_cmp_ui(y2, 1)>0){
    mpz_mod_ui(modTmp, y2, 2);
    if (mpz_cmp_ui(modTmp, 0)==0){//y = even
      mpz_mul(r, r, r); //r = r*r
      mpz_div_ui(y2, y2, 2); //y2 = y2/2
    }else{
      mpz_mul(n, n, r); //n = n*r
      mpz_mul(r, r, r); //r = r*r
      mpz_sub_ui(y2, y2, 1); //y2 --
      mpz_div_ui(y2, y2, 2); //y2 = y2/2
    }
  }
  mpz_mul(r, r, n);

  mpz_clear(n);
  mpz_clear(modTmp);
  mpz_clear(y2);

}

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet = NULL;

  int l = mpz_sizeinbase(i, 16);
  int size;
  if (l % 2 != 0) size = l+1;
  else size = l;
  octet = malloc(size+1);

  char* tmpStr = NULL;
  tmpStr = mpz_get_str(tmpStr, 16, i);
  gmp_printf("%d %ZX\n", size, i);
  for (int k = 0;k<size;k = k+2){
    octet[k] = toupper(tmpStr[size-k-2]);
    if ((size != l)&& (k == (size-2))) octet[k+1] = '0';
    else octet[k+1] = toupper(tmpStr[size-k-1]);
  }
  octet[size] = '\0';
  return octet;
}

//Convert octet string to integer
void oct2int(mpz_t i, const char* string){
  mpz_set_str(i, string, 16);
}

void interact( int* r, const char* l, const char* c){
  //Send l and c
  int size = strlen(c);
  fprintf( target_in, "%s\n", l );  fflush( target_in );
  fprintf( target_in, "%s\n", c );  fflush( target_in );

  //Receive result code from target
  if ( 1 != fscanf(target_out, "%d", r)){
    abort();
  }
}

//mpz_t N, e, ...
void attack() {
  mpz_t N;mpz_init(N);
  mpz_t e;mpz_init(e);
  mpz_t l;mpz_init(l);
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
  if( 1 != fscanf( data_in, "%s", lString ) ) {
      abort();
  }
  if( 1 != fscanf( data_in, "%s", cString ) ) {
      abort();
  }

  fclose(data_in);
  //Convert string to mpz_t
  oct2int(c, cString);

  //let B = 2^(8(k-1))
  int k = mpz_sizeinbase(N, 2);
  k = k/8;

  mpz_set_ui(B, 2);
  mpz_pow_ui(B, B, 8*(k-1));

  //let f1 = 2
  mpz_set_ui(f1, 2);

  while(r != 1){
  //Loop 1
    //send f1^e || c mod N
    mpz_powm(send, f1 ,e, N);
    mpz_mod(tmp, c, N);
    mpz_mul(send, send, tmp);
    mpz_mod(send, send, N);

    char* sendStr = int2oct(send);
    interact(&r, lString,sendStr);
    interaction++;
    gmp_printf("Loop 1 Result Code: %d f1: %Zd interaction: %d\n", r, f1, interaction);

    //if error != 1 then let f1 = 2*f1
    //if error == 1 then break
    if (r != 1) mpz_mul_ui(f1, f1, 2);
    free(sendStr);
  }

  //let f2 = floor((n+B)/B) * f1/2
  mpz_add(tmp, N, B);//N+B
  mpz_fdiv_q(tmp, tmp, B);
  mpz_div_ui(tmp2, f1, 2);
  mpz_mul(f2, tmp, tmp2);

  while(r != 0){
  //Loop2
    //send f2^e * c mod N
    mpz_powm(send, f2 ,e, N);
    mpz_mod(tmp, c, N);
    mpz_mul(send, send, tmp);
    mpz_mod(send, send, N);

    char* sendStr = int2oct(send);
    interact(&r, lString , sendStr);
    interaction++;
    int test = mpz_cmp(send, N);

    gmp_printf("%d %ZX\n%ZX\n%s\n",test, send, N, sendStr);
    gmp_printf("Loop 2 Result Code: %d f2: %Zd interaction: %d\n", r, f2, interaction);
    //if error == 1 let f2 = f2 + f1/2
    //if error != 0 break
    if (r == 1) mpz_add(f2, f2, tmp2);
    //else break;
  }

  //mmin = ceil(n/f2), mmax = floor((n+B)/f2)
  mpz_cdiv_q(mmin, N, f2);
  mpz_add(tmp, N, B);//N+B
  mpz_fdiv_q(mmax, tmp, f2);

//Loop3


while(mpz_cmp(mmin, mmax)!= 0){

  //chose ftmp where ftmp*m width is 2B
  //ftmp = floor(2B/(mmax - mmin))
  mpz_sub(tmp, mmax, mmin);
  mpz_mul_ui(tmp2, B, 2);
  mpz_fdiv_q(ftmp, tmp2, tmp);
  //select boundar point in+B, near the range of ftmp * m
  //i = floor((ftmp * mmin)/n)
  mpz_mul(tmp, ftmp, mmin);
  mpz_fdiv_q(in, tmp, N);
  mpz_mul(in, in, N);
  //let f3 = ceil(in/mmin)
  mpz_cdiv_q(f3, in, mmin);
  //send f3^e c mod N
  mpz_powm(send, f3 ,e, N);
  mpz_mod(tmp, c, N);
  mpz_mul(send, send, tmp);
  mpz_mod(send, send, N);

  char* sendStr = int2oct(send);
  interact(&r, lString,sendStr);
  interaction++;
  gmp_printf("Loop 3 Result Code: %d interaction: %d\n", r, interaction);
  //if error == 1 then set mmin = ceil((in+B)/f3)
  //if error != 1 then set mmax = floor((in+B)/f3)
    mpz_add(tmp, in, B);
  if (r == 1) {
    mpz_cdiv_q(mmin, tmp, f3);
  }
  else{
    mpz_fdiv_q(mmax, tmp, f3);
  }

}
gmp_printf("Target Material : %ZX\n", mmin);
gmp_printf("Total Number of Interaction: %d\n", interaction);

mpz_clear(N);
mpz_clear(e);
mpz_clear(l);
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
