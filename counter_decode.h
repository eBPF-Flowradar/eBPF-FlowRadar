#include "hashutils.h"
#include "flowradar.h"
#include <gsl/gsl_linalg.h>
#include <gsl/gsl_multifit.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef COUNTER_DECODE_H
#define COUNTER_DECODE_H
    
gsl_matrix * array_matrix_convert(double **eq_matrix, int counting_table_size, int num_purecells) {

    gsl_matrix *A = gsl_matrix_alloc(counting_table_size, num_purecells);

    if (A == NULL) {
        fprintf(stderr, "Memory allocation failed for A matrix.\n");
        return NULL;
    }

    // Copy data from array to gsl_matrix
    for (size_t i = 0; i < counting_table_size ; ++i) {
        for (size_t j = 0; j < num_purecells; ++j) {
            gsl_matrix_set(A, i, j, eq_matrix[i][j]);
        }
    }

    return A;
}

gsl_vector * array_vector_convert(double *pktcount_mtrx, int counting_table_size) {

    gsl_vector *b = gsl_vector_alloc(counting_table_size); // Allocate memory for gsl_vector

    if (b == NULL) {
        fprintf(stderr, "Memory allocation failed for b vector.\n");
        return NULL;
    }

    // Copy data from array to gsl_vector
    for (size_t i = 0; i < counting_table_size ; ++i) {
        gsl_vector_set(b, i, pktcount_mtrx[i]);
    }

    return b;
}

double * gsl_vector_to_array(const gsl_vector *x, int num_purecells) {

    double *array = (double *)malloc(num_purecells * sizeof(double));
    // Copy data from gsl_vector to array
    for (size_t i = 0; i < num_purecells; ++i) {
        array[i] = gsl_vector_get(x, i);
    }

    return array;
}

double * method_lsq(double **eq_matrix, double *pktcount_mtrx, int num_purecells, int counting_table_size) {

    gsl_matrix *A;
    gsl_vector *x;
    gsl_vector *b;
    gsl_matrix *cov;
    gsl_multifit_linear_workspace *work;
    double chisq;
    double *sol_array;

    // Allocate memory for A matrix
    A = array_matrix_convert(eq_matrix, counting_table_size, num_purecells);
    // Allocate memory for the solution vector x (n x 1)
    x = gsl_vector_alloc(num_purecells); 
    // x is a 2x1 vector
    // Allocate memory for the vector B (n x 1)
    b = array_vector_convert(pktcount_mtrx, counting_table_size);
    // Allocate memory for covariance
    cov = gsl_matrix_alloc(num_purecells, num_purecells);
    // Allocate memory for workspace
    // This workspace contains internal variables for fitting multi-parameter
    // models
    work = gsl_multifit_linear_alloc(counting_table_size, num_purecells);

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

int CD(struct flowset A, struct pureset_packet_count flowset_pktcount) {
    /*
        To run CounterDecode on the flowlist. The target is to solve Ax = B where
        B -> Packet counts and A is a binary matrix
    */
    int num_purecells = flowset_pktcount.flowset.latest_index;
    
    double ** eq_matrix = (double **)malloc(COUNTING_TABLE_SIZE * sizeof(double *));
    
    double * pktcount_matrix = (double *)malloc(COUNTING_TABLE_SIZE * sizeof(double));

    for (int i = 0; i < 30000; ++i) {
        pktcount_matrix[i] = flowset_pktcount.pktCount[i];
    }

    for (int i = 0; i < COUNTING_TABLE_SIZE; i++) {
        
        eq_matrix[i] = (double *)malloc(num_purecells * sizeof(double));
        
        for(int j = 0 ; j < num_purecells ; ++j){
            eq_matrix[i][j] = 0;
        }
    }

    for (int j = 0; j < num_purecells; j++) {

        __u128 flow_id = flowset_pktcount.flowset.purecells[j];

        for (int num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; num_hash++) {
            int entry_pos = jhash_key(flow_id, num_hash) % BUCKET_SIZE;
            int index = entry_pos + num_hash * BUCKET_SIZE;
            printf("index: %d\n", index);
            eq_matrix[index][j] = 1.0;
        }

    }

    double *sol_array = method_lsq(eq_matrix, pktcount_matrix, num_purecells, COUNTING_TABLE_SIZE);
    
    for (int i = 0; i < num_purecells; i++) {
        printf("Purecell:%d | Packet_count:%f\n", i, sol_array[i]);
    }

    free(pktcount_matrix);
    
    free(sol_array);

    for(int i = 0; i < COUNTING_TABLE_SIZE ; ++i) {
        free(eq_matrix[i]);
    }

    free(eq_matrix);

}
#endif
