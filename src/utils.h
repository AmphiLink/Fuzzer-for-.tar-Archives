#ifndef UTILS_H
#define UTILS_H

#include "definitions.h"

struct tests_info_t { // Struct to keep track of the status of various tests performed on the tar file
    int num_of_trials;
    int num_of_success;
    int num_of_no_output;

    int successful_with_empty_field;
    int successful_with_non_ASCII_field;
    int successful_with_non_numeric_field;
    int successful_with_non_null_terminated_field; 
    int successful_with_null_byte_in_middle;       
    int successful_with_non_null_bit_start;
    int successful_with_multiple_files;
    int successful_with_negative_value;
    int successful_with_null_field;
    int successful_with_short_field;
    int successful_with_non_octal_value;
    int successful_with_long_field;
    int successful_with_space_field;
    int successful_with_special_chars;


    int name_fuzzing_success;
    int mode_fuzzing_success;
    int uid_fuzzing_success;
    int gid_fuzzing_success;
    int size_fuzzing_success;
    int mtime_fuzzing_success;
    int typeflag_fuzzing_success;
    int linkname_fuzzing_success;
    int uname_fuzzing_success;
    int gname_fuzzing_success;
    int magic_fuzzing_success;
    int version_fuzzing_success;
};

typedef struct tar_t {
    char name[100]; 
    char mode[8]; 
    char uid[8]; 
    char gid[8]; 
    char size[12]; 
    char mtime[12]; 
    char chksum[8]; 
    char typeflag; 
    char linkname[100]; 
    char magic[6]; 
    char version[2]; 
    char uname[32]; 
    char gname[32]; 
    char devmajor[8]; 
    char devminor[8]; 
    char prefix[155]; 
    char padding[12]; 
}tar_t;

extern struct tests_info_t tests_info;

void init_tests_info(struct tests_info_t *ts);
void print_tests(struct tests_info_t *ts);
unsigned int calculate_checksum(struct tar_t* entry);
void generate_tar_header(struct tar_t *header);
void create_tar(tar_t* header, char* content_header, size_t content_header_size, char* end_data, size_t end_size);
void save_success(int attempt, const char *tar_file);
void delete_extracted_files();
void clear_terminal();
char generate_non_numeric_char();
#endif