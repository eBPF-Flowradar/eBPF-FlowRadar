#include "hashutils.h"
#include <gsl/gsl_linalg.h>
#include <gsl/gsl_multifit.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

gsl_matrix *array_matrix_convert(double **eq_matrix, int num_purecells) {

  gsl_matrix *A = gsl_matrix_alloc(COUNTING_TABLE_SIZE, num_purecells);

  if (A == NULL) {
    fprintf(stderr, "Memory allocation failed for A matrix.\n");
    return NULL;
  }

  // Copy data from array to gsl_matrix
  for (size_t i = 0; i < COUNTING_TABLE_SIZE; ++i) {
    for (size_t j = 0; j < num_purecells; ++j) {
      gsl_matrix_set(A, i, j, eq_matrix[i][j]);
    }
  }

  return A;
}

gsl_vector *array_vector_convert(double *pktcount_mtrx) {

  gsl_vector *b =
      gsl_vector_alloc(COUNTING_TABLE_SIZE); // Allocate memory for gsl_vector

  if (b == NULL) {
    fprintf(stderr, "Memory allocation failed for b vector.\n");
    return NULL;
  }

  // Copy data from array to gsl_vector
  for (size_t i = 0; i < COUNTING_TABLE_SIZE; ++i) {
    gsl_vector_set(b, i, pktcount_mtrx[i]);
  }

  return b;
}

double *gsl_vector_to_array(const gsl_vector *x, int num_purecells) {

  double *array = (double *)malloc(num_purecells * sizeof(double));
  // Copy data from gsl_vector to array
  for (size_t i = 0; i < num_purecells; ++i) {
    array[i] = gsl_vector_get(x, i);
  }

  return array;
}

double *method_lsq(double **eq_matrix, double *pktcount_mtrx,
                   int num_purecells) {

  gsl_matrix *A;
  gsl_vector *x;
  gsl_vector *b;
  gsl_matrix *cov;
  gsl_multifit_linear_workspace *work;
  double chisq;
  double *sol_array;

  // Allocate memory for A matrix
  A = array_matrix_convert(eq_matrix, num_purecells);
  // Allocate memory for the solution vector x (n x 1)
  x = gsl_vector_alloc(num_purecells); // x is a 2x1 vector
  // Allocate memory for the vecto B (n x 1)
  b = array_vector_convert(pktcount_mtrx);
  // Allocate memory for covariance
  cov = gsl_matrix_alloc(num_purecells, num_purecells);
  // Allocate memory for workspace
  // This workspace contains internal variables for fitting multi-parameter
  // models
  work = gsl_multifit_linear_alloc(COUNTING_TABLE_SIZE, num_purecells);

  // Perform least squares fitting
  gsl_multifit_linear(A, b, x, cov, &chisq, work);

  // Print the solution vector x
  sol_array = gsl_vector_to_array(x, num_purecells);

  // Free Workspace memory
  gsl_multifit_linear_free(work);
  // Free gsl_vector memory
  gsl_matrix_free(cov);
  gsl_vector_free(b);
  gsl_vector_free(x);
  // Free gsl_matrix memory
  gsl_matrix_free(A);

  return sol_array;
}

int counter_decode(struct pureset pure_set, __u32 pktCount[COUNTING_TABLE_SIZE]) {
  /*
      To run CounterDecode on the flowlist. The target is to solve Ax = B where
     B -> Packet counts and A is a binary matrix
      */

  double **eq_matrix = (double **)calloc(COUNTING_TABLE_SIZE, sizeof(double *));

  int num_purecells = pure_set.latest_index;

  double *pktcount_matrix =
      (double *)malloc(COUNTING_TABLE_SIZE * sizeof(double));

  for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {

    pktcount_matrix[i] = pktCount[i];
  }

  for (int i = 0; i < COUNTING_TABLE_SIZE; i++) {

    eq_matrix[i] = (double *)calloc(num_purecells, sizeof(double));
  }

  for (int j = 0; j < num_purecells; j++) {

    __u128 flow_id = pure_set.purecells[j];

    for (int num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; num_hash++) {

      int entry_pos = jhash_key(flow_id, num_hash)%COUNTING_TABLE_SIZE;

      eq_matrix[entry_pos][j] = 1.0;
    }
  }

  double *sol_array = method_lsq(eq_matrix, pktcount_matrix, num_purecells);
  printf("\nCounter Decode complete...\n");

  FILE *fptr;
  fptr=fopen("cd_logs.csv","a");

  if (fptr == NULL) {
    perror("Error opening file");
    return -1;  // or handle the error as needed
  }

  for (int i = 0; i < num_purecells; i++) {
      printf("Purecell: ");
      printf("%" PRIx64 "%016" PRIx64,
             (uint64_t)(pure_set.purecells[i] >> 64),
             (uint64_t)pure_set.purecells[i]);
    printf(" | Packet_count:%d\n",(int) round(sol_array[i]));  //rounding off to nearest integer
    
    //write to log file
    fprintf(fptr,"%lu,",(unsigned long)time(NULL));  //timestamp
    fprintf(fptr,"%" PRIx64 "%016" PRIx64",",
             (uint64_t)(pure_set.purecells[i] >> 64),
             (uint64_t)pure_set.purecells[i]);
    fprintf(fptr,"%d\n",(int)round(sol_array[i]));  //rounding off to nearest integer
  }

  fclose(fptr);

  //free all memory
  for (int i = 0; i < COUNTING_TABLE_SIZE; i++) {
    free(eq_matrix[i]);
  }
  free(eq_matrix);
  free(pktcount_matrix);
  free(sol_array);
}
