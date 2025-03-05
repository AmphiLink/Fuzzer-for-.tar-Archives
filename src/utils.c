#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fnmatch.h>
#include "utils.h"

struct tests_info_t tests_info;
/**
 * This function initializes the tests_info_t structure by setting all its values to 0.
 * @param ts Pointer to the tests_info_t structure to initialize.
 */
void init_tests_info(struct tests_info_t *ts) {
    memset(ts, 0, sizeof(int)*26);
}

/**
 * This function prints the test results stored in the tests_info_t structure.
 * @param ts Pointer to the tests_info_t structure containing test results.
 * The output shows which fields were tested successfully and is useful for debugging.
 */
void print_tests(struct tests_info_t *ts) {
    printf("\n\nTests:\n");
    printf("Number of trials : %d\n", ts->num_of_trials);
    printf("Number of success: %d\n", ts->num_of_success);
    printf("Number of no output: %d\n\n", ts->num_of_no_output);
    printf("Success with Tests: \n");
    printf("\t   Empty field                           : %d\n", ts->successful_with_empty_field);
    printf("\t   non ASCII field                       : %d\n", ts->successful_with_non_ASCII_field);
    printf("\t   non numeric field                     : %d\n", ts->successful_with_non_numeric_field);
    printf("\t   non null terminated field             : %d\n", ts->successful_with_non_null_terminated_field); 
    printf("\t   null byte in the middle of field      : %d\n", ts->successful_with_null_byte_in_middle);  
    printf("\t   non null bit start                    : %d\n", ts->successful_with_non_null_bit_start); 
    printf("\t   Negative value                        : %d\n", tests_info.successful_with_negative_value);
    printf("\t   NULL field                            : %d\n", tests_info.successful_with_null_field);
    printf("\t   Short field                           : %d\n", tests_info.successful_with_short_field);
    printf("\t   multiple files                        : %d\n", ts->successful_with_multiple_files);
    printf("\t   Non-Octal value                       : %d\n", ts->successful_with_non_octal_value);
    printf("\t   Long field                            : %d\n", tests_info.successful_with_long_field);
    printf("\t   Space field                           : %d\n", tests_info.successful_with_space_field);
    printf("\t   Special chars                         : %d\n", tests_info.successful_with_special_chars);
    printf("Success with header's fields: \n");
    printf("\t   name field                            : %d\n", ts->name_fuzzing_success);
    printf("\t   mode field                            : %d\n", ts->mode_fuzzing_success);
    printf("\t   uid field                             : %d\n", ts->uid_fuzzing_success);
    printf("\t   gid field                             : %d\n", ts->gid_fuzzing_success);
    printf("\t   size field                            : %d\n", ts->size_fuzzing_success);
    printf("\t   mtime field                           : %d\n", ts->mtime_fuzzing_success);
    printf("\t   typeflag field                        : %d\n", ts->typeflag_fuzzing_success);
    printf("\t   linkname field                        : %d\n", ts->linkname_fuzzing_success);
    printf("\t   uname field                           : %d\n", ts->uname_fuzzing_success);
    printf("\t   gname field                           : %d\n", ts->gname_fuzzing_success);
    printf("\t   magic field                           : %d\n", ts->magic_fuzzing_success);
    printf("\t   version field                         : %d\n", ts->version_fuzzing_success);
}

/**
 * This function calculates the checksum of a tar entry and updates its checksum field.
 * @param entry Pointer to the tar_t structure representing a tar entry.
 * @return The calculated checksum as an unsigned integer.
 */
unsigned int calculate_checksum(struct tar_t* entry) {
    memset(entry->chksum, ' ', 8);
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++) check += raw[i];
    snprintf(entry->chksum, 8, "%06o0", check);
    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

/**
 * This function generates a tar header with randomized values for testing purposes.
 * @param header Pointer to the tar_t structure to be initialized.
 */
void generate_tar_header(struct tar_t *header) {
    int x = rand() % 1000 + 1;
    char filename[100];
    snprintf(filename, sizeof(filename), "file_%d.txt", x);
    char linkname[100] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    memset(header, 0, sizeof(tar_t));

    snprintf(header->name, TAR_NAME_LENGTH, "%s",filename);
    snprintf(header->mode, sizeof(header->mode), "07777");
    snprintf(header->uid, sizeof(header->uid), "%s","0000000");
    snprintf(header->gid, sizeof(header->gid), "%s","0000000");
    snprintf(header->size, sizeof(header->size),"%011o", 0);
    snprintf(header->mtime, sizeof(header->mtime),"%011lo", time(NULL));
    header->typeflag = REGTYPE;
    snprintf(header->linkname, sizeof(header->linkname), "%s", linkname);
    snprintf(header->uname, sizeof(header->uname), "student-linfo2347");
    snprintf(header->gname, sizeof(header->gname), "student-linfo2347");
    snprintf(header->magic, sizeof(header->magic),TAR_MAGIC);
    snprintf(header->version, sizeof(header->version) + 1,TAR_VERSION);
    snprintf(header->devmajor, sizeof(header->devmajor),"%s", "0000000");
    snprintf(header->devminor, sizeof(header->devminor),"%s", "0000000");
    calculate_checksum(header);
}

/**
 * This function creates a TAR archive and writes the provided data to it.
 * @param header Pointer to the tar header structure.
 * @param content_header Pointer to the content header data.
 * @param content_header_size Size of the content header data.
 * @param end_data Pointer to the end data block.
 * @param end_size Size of the end data block.
 */
void create_tar(tar_t* header, char* content_header, size_t content_header_size, char* end_data, size_t end_size) {
    char* file_name = "Archive.tar";
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    
    if (fwrite(header, sizeof(tar_t), 1, file) != 1) {
        perror("Error writing header");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (content_header_size > 0 && fwrite(content_header, content_header_size, 1, file) != 1) {
        perror("Error writing content");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (end_size > 0 && fwrite(end_data, end_size, 1, file) != 1) {
        perror("Error writing end bytes");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (fclose(file) != 0) {
        perror("Error closing file");
        exit(EXIT_FAILURE);
    }
    
}

/**
 * This function saves a successfully generated TAR file by renaming it with a success prefix.
 * @param attempt The attempt number for naming the file.
 * @param tar_file The name of the original TAR file to be saved.
 */
void save_success(int attempt, const char *tar_file) {
    char dest[256];
    snprintf(dest, sizeof(dest), "./success_%d_%s", attempt, tar_file);

    FILE *src = fopen(tar_file, "rb");
    if (!src) {
        printf("Failed to open the source file: %s\n", tar_file);
        return;
    }

    FILE *dst = fopen(dest, "wb");
    if (!dst) {
        printf("Failed to open the destination file: %s\n", dest);
        fclose(src);
        return;
    }

    char buffer[1024];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, n, dst);
    }

    if (fclose(src) != 0) {
    perror("Error closing source file");
    }
    if (fclose(dst) != 0) {
        perror("Error closing destination file");
    }

    printf("Archive saved as %s\n", dest);
}

/**
 * This function deletes extracted files from the current directory while preserving important ones.
 */
void delete_extracted_files() {
    if (strcmp(DELETE_SUCCESS, "True") == 0){
        system("find . ! -name '.gitignore' ! -name 'extractor_apple' ! -name 'extractor_x86_64' ! -name 'fuzzer_statement.pdf' ! -name 'main.c' ! -name 'README.md' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'Makefile' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete > /dev/null 2>&1");
    } else {
        system("find . ! -name '.gitignore' ! -name 'extractor_apple' ! -name 'extractor_x86_64' ! -name 'fuzzer_statement.pdf' ! -name 'main.c' ! -name 'README.md' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'Makefile' ! -name 'success_*' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete > /dev/null 2>&1");
    }
}

/**
 * This function clears the terminal screen based on the operating system.
 */
void clear_terminal() {
    // Verify if the system is Unix ou Sindows 
    #ifdef _WIN32
        system("cls");  // Command pour Windows
    #else
        system("clear");  // Command pour Unix (Linux, macOS)
    #endif
}


/**
 * This function generates a non-numeric ASCII character, either a letter or a symbol.
 * @return A randomly chosen non-numeric character.
 */
char generate_non_numeric_char() {
    
    char c;
    int choice = rand() % 2;
    if (choice == 0) {
       
        c = (rand() % 26) + (rand() % 2 == 0 ? 'A' : 'a');
    } else {
        
        const char symbols[] = "!@#$%^&*()_-+=<>?";
        c = symbols[rand() % (sizeof(symbols) - 1)];
    }
    return c;
}