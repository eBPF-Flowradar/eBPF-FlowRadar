#include <stdio.h>
#include "flowradar.h"
#include "hashutils.h"
#include <stdlib.h>
#include <gsl/gsl_linalg.h>
#include <gsl/gsl_multifit.h>

#ifndef COUNTER_DECODE_H
#define COUNTER_DECODE_H

gsl_matrix* array_matrix_convert(double** eq_matrix,int num_purecells){

    gsl_matrix *A = gsl_matrix_alloc(COUNTING_TABLE_SIZE,num_purecells);

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

gsl_vector* array_vector_convert(double* pktcount_mtrx){
    
    gsl_vector* b = gsl_vector_alloc(COUNTING_TABLE_SIZE); // Allocate memory for gsl_vector

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

double* gsl_vector_to_array(const gsl_vector *x,int num_purecells) {

    double* array = (double*)malloc(num_purecells* sizeof(double)); 
    // Copy data from gsl_vector to array
    for (size_t i = 0; i < num_purecells; ++i) {
        array[i] = gsl_vector_get(x, i);
    }

    return array;
}

double* method_lsq(double** eq_matrix, double* pktcount_mtrx, int num_purecells) {

    gsl_matrix* A;
    gsl_vector* x;
    gsl_vector* b;
    gsl_matrix* cov;
    gsl_multifit_linear_workspace* work;
    double chisq;
    double* sol_array;

    // Allocate memory for A matrix
    A = array_matrix_convert(eq_matrix, num_purecells);
    // Allocate memory for the solution vector x (n x 1)
    x = gsl_vector_alloc(num_purecells); // x is a 2x1 vector
    // Allocate memory for the vecto B (n x 1)
    b = array_vector_convert(pktcount_mtrx);
    // Allocate memory for covariance
    cov = gsl_matrix_alloc(num_purecells, num_purecells);
    //Allocate memory for workspace
    //This workspace contains internal variables for fitting multi-parameter models
    work = gsl_multifit_linear_alloc(COUNTING_TABLE_SIZE, num_purecells);
    
    // Perform least squares fitting
    gsl_multifit_linear(A, b, x, cov, &chisq, work);
    
    // Print the solution vector x
    sol_array = gsl_vector_to_array(x, num_purecells);

    
    //Free Workspace memory
    gsl_multifit_linear_free(work);
    // Free gsl_vector memory
    gsl_matrix_free(cov);
    gsl_vector_free(b);
    gsl_vector_free(x);
    // Free gsl_matrix memory
    gsl_matrix_free(A);

    return sol_array;
}

int CD(struct flowset A, struct pureset_packet_count flowset_pktcount){
    /*
	To run CounterDecode on the flowlist. The target is to solve Ax = B where B -> Packet counts and A is a binary matrix
	*/

    double** eq_matrix = (double**)calloc(COUNTING_TABLE_SIZE,sizeof(double*));
    
    int num_purecells = flowset_pktcount.flowset.latest_index;
    
    double* pktcount_matrix = (double *) malloc(COUNTING_TABLE_SIZE * sizeof(double));
    
    for(int  i = 0; i < 30000 ; ++i) {

        pktcount_matrix[i] = flowset_pktcount.pktCount[i];
    
    }

    for(int i=0;i<COUNTING_TABLE_SIZE;i++){
    
        eq_matrix[i]=(double*)calloc(num_purecells,sizeof(double));
    
    }

    for(int j=0;j<num_purecells;j++){
        
        __u128 flow_id = flowset_pktcount.flowset.purecells[j];
        
        for(int num_hash = 0; num_hash < NUM_HASH_FUNCTIONS ; num_hash++){
            
            int entry_pos = jhash_key(flow_id, num_hash);
            
            eq_matrix[entry_pos][j] = 1.0;
        }
    
    }   

    double* sol_array = method_lsq(eq_matrix,pktcount_matrix,num_purecells);
    
    for(int i = 0 ; i<num_purecells;i++){
    
        printf("Purecell:%d | Packet_count:%f",i,sol_array[i]);
    
    }

    free(eq_matrix);
}

#endif
