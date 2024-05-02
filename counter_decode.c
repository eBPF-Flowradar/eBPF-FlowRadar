#include "murmur.h"
#include "flowradar.h"
#include <gsl/gsl_linalg.h>
#include <gsl/gsl_multifit.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

int counter_decode(struct pureset *pure_set, double *pktCount) {
  /*
      To run CounterDecode on the flowlist. The target is to solve Ax = B where
     B -> Packet counts and A is a binary matrix
      */

  int num_purecells = pure_set->latest_index;
  
  //gsl_matrix_calloc initializes all elements to zero
  gsl_matrix *A= gsl_matrix_calloc(COUNTING_TABLE_SIZE, num_purecells);
  // Allocate memory for the solution vector x (n x 1)
  gsl_vector *x= gsl_vector_alloc(num_purecells);
  // Allocate memory for B;
  gsl_vector *B= gsl_vector_alloc(COUNTING_TABLE_SIZE); 
  // Allocate memory for covariance
  gsl_matrix *cov= gsl_matrix_alloc(num_purecells, num_purecells);
  // allocate memory for workspace
  gsl_multifit_linear_workspace *work=gsl_multifit_linear_alloc(COUNTING_TABLE_SIZE, num_purecells);
  
  double chisq;


  if (!A || !x || !B || !cov || !work) {
    fprintf(stderr, "Memory allocation failed\n");
    return -1;
  }

  // Fill A matrix
  for (size_t i = 0; i < num_purecells; ++i) {

      __u128 flow_id = pure_set->purecells[i];

    for (size_t num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; ++num_hash) {

      //generate hash
      __u32 offset;
      MurmurHash3_x86_32(&flow_id,16,num_hash,&offset);
      offset=offset%COUNTING_TABLE_ENTRIES_PER_SLICE;
      __u32 hashIndex=num_hash*COUNTING_TABLE_ENTRIES_PER_SLICE+offset;

      gsl_matrix_set(A, hashIndex,i,1);
    }
  }

  // Copy data from array to gsl_vector
  gsl_vector_view v = gsl_vector_view_array(pktCount,COUNTING_TABLE_SIZE);
  gsl_vector_memcpy(B, &v.vector);

  
  // Perform least squares fitting
  printf("Solving equations!!\n");
  gsl_multifit_linear(A, B, x, cov, &chisq, work);

  
  printf("Counter Decode complete...\n");

  printf("Writing to log file\n");
  FILE *fptr;
  fptr=fopen(COUNTER_DECODE_LOG_FILE,"a");

  if (fptr == NULL) {
    perror("Error opening file");
    return -1;  // or handle the error as needed
  }

  for (int i = 0; i < num_purecells; i++) {
    //   printf("Purecell: ");
    //   printf("%" PRIx64 "%016" PRIx64,
    //          (uint64_t)(pure_set.purecells[i] >> 64),
    //          (uint64_t)pure_set.purecells[i]);
    // printf(" | Packet_count:%d\n",(int) round(sol_array[i]));  //rounding off to nearest integer
    
    //write to log file
    fprintf(fptr,"%lu,",(unsigned long)time(NULL));  //timestamp
    fprintf(fptr,"%" PRIx64 "%016" PRIx64",",
             (uint64_t)(pure_set->purecells[i] >> 64),
             (uint64_t)pure_set->purecells[i]);
    fprintf(fptr,"%d\n",(int)round(gsl_vector_get(x,i)));  //rounding off to nearest integer
  }

  fclose(fptr);
  printf("Write complete\n");

  // Free memory that is used
  gsl_multifit_linear_free(work);
  gsl_matrix_free(cov);
  gsl_vector_free(B);
  gsl_vector_free(x);
  gsl_matrix_free(A);

  return 0;
}
