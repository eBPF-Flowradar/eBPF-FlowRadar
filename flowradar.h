#define FLOWFILTER_SIZE 100
#define COUNTINGTABLE_SIZE 100
#define MAX_PURE_CELLS COUNTINGTABLE_SIZE * 2
#define NUM_HASH_FUNCTIONS 5

struct pureset {
  int purecells[MAX_PURE_CELLS];
  int latest_index;
};

struct ct_data {
  int flowxor;
  int flow_count;
  int packet_count;
};

struct flowset {
  struct ct_data ct[COUNTINGTABLE_SIZE];
  int flowfilter[FLOWFILTER_SIZE];
};
