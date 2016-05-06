#include "attack.h"
#include "math.h"
#include "time.h"
#include "limits.h"
#include "ctype.h"
#include "float.h"

#define BUFFER_SIZE ( 80 )
#define BYTE 256
#define OCTET 16
//Sample plaintext number
#define M_SIZE 200



/*------------------------------------------
  GLOBAL VARIABLES FOR INTERACTION
--------------------------------------------*/
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


/*------------------------------------------
  GLOBAL VARIABLES FOR STORING DATA
--------------------------------------------*/
//char* pt  = "3243F6A8885A308D313198A2E0370734";
//char* pt2 = "00112233445566778899AABBCCDDEEFF";
//char* keyText ="7D8240FDE97950E05DEF3566616DDEED";
uint8_t pt[OCTET] =
{ 0x32, 0x43, 0xF6, 0xA8,
  0x88, 0x5A, 0x30, 0x8D,
  0x31, 0x31, 0x98, 0xA2,
  0xE0, 0x37, 0x07, 0x34 };

uint8_t plaintext[M_SIZE][OCTET];   //The set of plaintext
uint8_t intermediate[M_SIZE][BYTE]; //The set of intermediate value
uint8_t h[M_SIZE][BYTE];            //The set of hyothetical power value
uint8_t keyArray[OCTET]={0};        //The key detected
float* traceDif;


double sumA=0, sumB=0;
uint8_t* traceTmp;
int traceLength=0;

//S-box lookup table
uint8_t s[256] =
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

//inverse S-box lookup table
uint8_t inv_s[256] =
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

//Interact with given taret and get length of traces
int find_length(FILE* fp){
  //Receive length of trace
  int length = 0;
  //Read letters until it meets first comma
  char a=fgetc(fp);
  while(a!=','){
    if (a =='\n')
    {
      a=fgetc(fp);
      continue;
    }
    length = length * 10 + (a-'0');
    a=fgetc(fp);
  }
  return length;
}

//Interact with given target and get traces
void find_trace(FILE* fp, int length){
  //Allocate length size of array
  if (length != traceLength){
    traceLength = length;
    traceTmp = malloc(length*sizeof(uint8_t));
    if (traceTmp==NULL) exit(0);
  }
  char a=fgetc(fp);
  int index=0;
  uint8_t tmp = 0;
  //Until the end of line
  while(a!='\n'){
    if(a==','){
      traceTmp[index]=tmp;
      index++;
      tmp=0;
    }
    else tmp = tmp*10+(a -'0');
    a=fgetc(fp);
  }
}

//Interact with D
//Return int array that contains power consumption trace
void interact(int *l, mpz_t c, const uint8_t m[OCTET]){
  //Send m
  for (int i = 0;i<OCTET;i++)
  {
    gmp_fprintf(target_in, "%X", m[i]); fflush(target_in);
  }
  gmp_fprintf(target_in, "\n"); fflush(target_in);
  //Receive length and traces
  int length = find_length(target_out);
  find_trace(target_out, length);

  *l = length;
  //Receive c
  if (gmp_fscanf(target_out, "%ZX", c) == 0) { abort(); }
  interaction++;
  //return traceTmp;
}

//Interact with Replica
void interact_R( int* l, mpz_t c, const uint8_t* m, const uint8_t* k){
  //Send m and k
  for (int i = 0;i<OCTET;i++)gmp_fprintf(R_in, "%X",m[i]); fflush(R_in);
  gmp_fprintf(R_in, "\n"); fflush(R_in);

  for (int i = 0;i<OCTET;i++)gmp_fprintf(R_in, "%X",k[i]); fflush(R_in);
  gmp_fprintf(R_in, "\n"); fflush(R_in);

  //Receive length and traces
  int length = find_length(R_out);
  find_trace(R_out, length);
  *l = length;
  //Receive ciphertext
  if (gmp_fscanf(R_out, "%ZX", c) == 0) { abort(); }
  interaction++;
}

//Convert integer to octet string
char* int2oct(const mpz_t i){
  char* octet = NULL;
  uint8_t size = 32;
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

//Function to convert octet string into state matrix
void convertToIntArray(uint8_t* array, char* ct){
  static char tmp[3];
  tmp[2] = '\0';
  //Take two letters from string and store it in matrix
  for (int i = 0;i<strlen(ct);i=i+2){
      tmp[0] = ct[i];
      tmp[1] = ct[i+1];
      array[(i/2)]=(int)strtol(tmp, NULL, 16);
  }
}

void generatePlaintext(){
  srand(time(NULL));
  for (int i = 1;i < M_SIZE;i++){
    for (int j = 0; j < OCTET; j++) {
        plaintext[i][j] = (uint8_t) rand() % BYTE;
    }
  }
  printf("Plaintexts Generation ENDS.\n");
}



void attack() {
  mpz_t c;      mpz_init(c);
  mpz_t c_R;      mpz_init(c_R);

  int l;
  interact(&l, c, pt);
  gmp_printf("i: %d Ciphertext: %ZX\n", interaction, c);
  gmp_printf("Length: %d\n",l);
  //Set first plaintext
  for (int i = 0;i<OCTET;i++) plaintext[0][i]= pt[i];

  //Traces
  uint8_t t[M_SIZE][l];
  //Set first trace
  for (int i = 0;i<l;i++)  t[0][i] = traceTmp[i];

  //Difference Array resize
  traceDif = malloc(sizeof(float)*l);
  if (traceDif == NULL) exit(0);

  //Generate M_SIZE number of plaintext
  generatePlaintext();

  //Get trace for each plaintext
  printf("Traces Generation STARTS...\n");
  for (int i = 1; i < M_SIZE;i++){
    interact(&l, c, plaintext[i]);
    for (int j = 0;j<l;j++)  t[i][j] = traceTmp[j];
  }
  printf("Traces Generation ENDS.\n");

  //For each byte in plaintext
  for (int b = 0;b<OCTET;b++){
    printf("Key byte: %d\n", b);
    //Calculate intermediate value and hyothetical power value
    //For each plaintext
    for (int i = 0;i < M_SIZE; i++){
      //Guess the key value
      for (int ki = 0;ki < BYTE; ki++){
        intermediate[i][ki] = s[plaintext[i][b]^(uint8_t)ki];
        h[i][ki] = intermediate[i][ki] & 1;
      }
    }

    float max_correlation = 0;
    float max = 0, min = FLT_MAX;
    for (int ki = 0;ki<BYTE;ki++){

      for (int j = 0;j<l;j++){
        //Calculate Mean
        double R=0;
        double sum_H=0, sum_T = 0;
        for (int i = 0;i<M_SIZE;i++){
          sum_H += h[i][ki];
          sum_T += t[i][j];
        }
        double mean_H = sum_H/(double)M_SIZE;
        double mean_T = sum_T/(double)M_SIZE;

        printf("%f\n", mean_H);
        //Calculate Sample Standard Deviation
        sum_H=0; sum_T=0;
        for (int i = 0;i<M_SIZE;i++){
          sum_H +=(h[i][ki] - mean_H);
          sum_T +=(t[i][j] - mean_T);
          printf("%f %f\n", sum_H, h[i][ki]);
        }
        double s_H = sqrt(sum_H/(double)(M_SIZE-1));
        double s_T = sqrt(sum_T/(double)(M_SIZE-1));

        //Calculate Correlation coefficient
        R =0;
        for (int i = 0;i<M_SIZE;i++){
          R =R + ((h[i][ki] - mean_H)/s_H)*((t[i][j] - mean_T)/s_T);
        }
        printf("%f\n", R);
        R = R/(M_SIZE - 1);
        if (R> max) max = R;
        if (R < min) min = R;
      }
      if (max-min > max_correlation){
        keyArray[b]= (uint8_t)ki;
        max_correlation = max-min;
      }

    }
  }
  //Check the found key is correct or not by using Replica

  interact(&l, c, pt);

  gmp_printf("%ZX\n", c);
  interact_R(&l, c_R, pt, keyArray);
  gmp_printf("%ZX\n", c_R);
  //END
  printf("Target Material : ");
  for (int i = 0;i<OCTET;i++){
    if (keyArray[i]<OCTET) printf("0");
    printf("%X", keyArray[i]);
  }
  printf("\n");
  gmp_printf("Total Number of Interaction: %d\n", interaction);
  //mpz_clear(m);
  mpz_clear(c);
  mpz_clear(c_R);

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
