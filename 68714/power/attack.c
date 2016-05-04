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

char* pt  = "3243F6A8885A308D313198A2E0370734";
char* pt2 = "00112233445566778899AABBCCDDEEFF";

char* keyText = "1FF32EE1416B13A313C12F9EC2782CB0";
int* interact(int*l, mpz_t c, const mpz_t m){
  //Send c
  gmp_fprintf(target_in, "%ZX\n",m); fflush(target_in);
  //Receive execution time and plaintext from target
//  if ( 1 != fscanf(target_out, "%s", p)){ abort(); }
char a=fgetc(R_out);
int length = 0;
while(a!=','){
  length = length * 10 + (a-'0');
  a=fgetc(R_out);
}
int* p = malloc(length*sizeof(int));
if (p==NULL) exit(0);
a=fgetc(R_out);
int index=0;
int tmp=0;
while(a!='\n'){
  if(a==','){
    p[index]=tmp;
    index++;
    tmp=0;
  }
  else{
    tmp = tmp*10+(a -'0');
  }
  a=fgetc(R_out);
}
*l = length;
  //if( 1 != fscanf( target_out, "%s", p ) ) { abort();}
  if (gmp_fscanf(target_out, "%ZX", c) == 0) { abort(); }
  interaction++;
  return p;
}
//call by seprateTrace(&v, consumption, trace)
int separateTrace( int* consumption, char* trace){
int i = 0;
int length = 0;
//get length
  while(trace[i]!='\0'){
    if (trace[i]==','){
      char sub[5];
      for(int j = 0;j<i;j++){
        sub[j] = trace[j];
      }
      length = (int)strtol(sub, NULL, 10);
      break;
    }
    i++;
  }
  consumption = malloc(sizeof(int)*length);
  char subStr[3];
  int index = 0;
  int indexC = 0;
  int k  = 0;
  while(trace[k]!='\0'){
    if (k<i) {k++;continue;}
    if (trace[k]==','){
      consumption[indexC]= (int)strtol(subStr, NULL, 10);
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
  return length;
}

int* interact_R( int* l, mpz_t c, const mpz_t m, const mpz_t k){
  //Send c, N, d

  gmp_fprintf(R_in, "%ZX\n", m); fflush(R_in);
  gmp_fprintf(R_in, "%ZX\n", k); fflush(R_in);
  //Receive execution time and plaintext from target
  //if ( 1 != fscanf(R_out, "%s", p)){ abort(); }
  char a=fgetc(R_out);
  int length = 0;
  while(a!=','){
    length = length * 10 + (a-'0');
    a=fgetc(R_out);
  }
  int* p = malloc(length*sizeof(int));
  if (p==NULL) exit(0);
  a=fgetc(R_out);
  int index=0;
  int tmp=0;
  while(a!='\n'){
    if(a==','){
      p[index]=tmp;
      index++;
      tmp=0;
    }
    else{
      tmp = tmp*10+(a -'0');
    }
    a=fgetc(R_out);
  }
  *l = length;
  if (gmp_fscanf(R_out, "%ZX", c) == 0) { abort(); }
  interaction++;
  return p;
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
//mpz_t N, e, ...
void attack() {
/*
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
*/
  mpz_t m;      mpz_init(m);
  mpz_t c;      mpz_init(c);
  mpz_t key;      mpz_init(key);

  //char* pt ="3243F6A8885A308D313198A2E0370734";
  oct2int(m, pt);
  oct2int(key, keyText);
  int* trace;
  int l;
  //interact(trace, c, m);
  trace = interact(&l, c, m);
  gmp_printf("cipher: %ZX\n", c);
  trace = interact_R(&l, c, m, key);
  gmp_printf("length: %d\n",l);
  for(int i = 0;i<l;i++){
    printf("%d\n", trace[i]);
  }
  gmp_printf("cipher: %ZX\n%ZX\n", c, key);
  //gmp_printf("trace: %s\ncipher: %ZX\n",trace, c);
  int * consumption ={0};
  //int l = separateTrace(consumption, trace);
//  for (int i = 0;i<l;i++){
    //gmp_printf("%d \n", consumption[i]);
  //}

  //END
  //gmp_printf("Target Material : %ZX\n", dFinal);
  //gmp_printf("Total Number of Interaction: %d\n", interaction);
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
