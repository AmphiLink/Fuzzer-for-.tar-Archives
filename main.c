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

#define BLOCK_SIZE 512
#define TAR_NAME_LENGTH 100

#define TAR_MAGIC "ustar"
#define TAR_VERSION "00"

#define REGTYPE  '0'

#define MAX_TRIES 500

#pragma pack(1)  // S'assurer que la structure fait exactement 512 octets
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

static tar_t header;

char* path_extractor;
char* file_name;


struct tests_info_t { // Struct to keep track of the status of various tests performed on the tar file
    int num_of_trials;
    int num_of_success;
    int num_of_no_output;

    int successful_with_empty_field;
    int successful_with_non_ASCII_field;
    int successful_with_non_numeric_field;

    int name_fuzzing_success;
    int mode_fuzzing_success;
};

struct tests_info_t tests_info;

void init_tests_info(struct tests_info_t *ts) {
    memset(ts, 0, sizeof(int)*28);
}

void print_tests(struct tests_info_t *ts) {
    printf("\n\nTests:\n");
    printf("Number of trials : %d\n", ts->num_of_trials);
    printf("Number of success: %d\n", ts->num_of_success);
    printf("Number of no output: %d\n\n", ts->num_of_no_output);
    printf("Success with \n");
    printf("\t     Empty field                       : %d\n", ts->successful_with_empty_field);
    printf("\t     non ASCII field                   : %d\n", ts->successful_with_non_ASCII_field);
    printf("\t     non numeric field                 : %d\n", ts->successful_with_non_numeric_field);
    printf("Success on \n");
    printf("\t   name field       : %d\n", ts->name_fuzzing_success);
    printf("\t   mode field       : %d\n", ts->mode_fuzzing_success);
}



void trim(char *str) {
    int start = 0, end = strlen(str) - 1;
    while (isspace((unsigned char)str[start])) start++;
    while (end > start && isspace((unsigned char)str[end])) end--;
    memmove(str, str + start, end - start + 1);
    str[end - start + 1] = '\0';
}

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

void generate_octal_value(char *buffer, size_t size, unsigned int max_value) {
    unsigned int value = rand() % max_value;
    snprintf(buffer, size, "%0*o", (int)(size - 1), value);
}

void generate_tar_header(struct tar_t *header) {
    char linkname[100] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    memset(header, 0, sizeof(struct tar_t));

    snprintf(header->name, TAR_NAME_LENGTH, "file_%d.txt", rand() % 1000);
    snprintf(header->mode, sizeof(header->mode), "07777");
    snprintf(header->uid, sizeof(header->uid), "0000000");
    snprintf(header->gid, sizeof(header->gid), "0000000");
    snprintf(header->size, sizeof(header->size), 0);
    snprintf(header->mtime, sizeof(header->mtime), time(NULL));
    header->typeflag = REGTYPE;
    snprintf(header->linkname, sizeof(header->linkname), "link_%d", rand() % 100);
    snprintf(header->uname, sizeof(header->uname), "student-linfo2347");
    snprintf(header->gname, sizeof(header->gname), "student-linfo2347");
    strncpy(header->magic, TAR_MAGIC, 6);
    strncpy(header->version, TAR_VERSION, 2);
    snprintf(header->devmajor, sizeof(header->devmajor),"%s", "0000000");
    snprintf(header->devminor, sizeof(header->devminor),"%s", "0000000");
    calculate_checksum(header);
}

void create_tar(tar_t* header, char* content_header, size_t content_header_size, char* end_data, size_t end_size) {
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    
    if (fwrite(header, sizeof(header), 1, file) != 1) {
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
    
    fclose(file);
}

void create_base_tar(tar_t* header) {
    char end_data[BLOCK_SIZE*2];
    memset(end_data, 0, BLOCK_SIZE*2);
    create_tar(header, NULL, 0, end_data, BLOCK_SIZE*2);
}


void fuzz_field(char *field, size_t field_size) { // prend en compte la taille et le type de test avec un pointeur vers le champ à tester 
    memset(field, 0, field_size); // Nettoie tout avant les tests et initialise avec des 0

    // Test 1 : Empty field
    generate_tar_header(&header);
    strncpy(field, "", field_size);
    create_base_tar(&header);
    if(extract(path_extractor) == 1){
        tests_info.successful_with_non_ASCII_field++;
    }

    // Test 2 : 
    for (size_t i = 0; i < field_size - 1; i++) {
        field[i] = 128 + (rand() % 128); 
    }
    field[field_size - 1] = '\0';

    // Test 3 : Caractères non numériques (Ajout de lettre au hasard pour vérif si c'est pas dans des caractère non numérique)
    for (size_t i = 0; i < field_size - 1; i++) {
        field[i] = 'A' + (rand() % 26); 
    }
    field[field_size - 1] = '\0';

    calculate_checksum(&header); // ça calcule la checksum du header pour verifier si les changements sont bien pris en compte 
}

void name_fuzzing() {
    printf("\n~~~ Name header Fuzzing ~~~\n");
    fuzz_field(header.name, sizeof(header.name));
}

void mode_fuzzing() {
    printf("\n~~~ Mode header Fuzzing ~~~\n");
    fuzz_field(header.mode, sizeof(header.mode));
}

void size_fuzzing() {
    printf("\n~~~ Size header Fuzzing ~~~\n");
    fuzz_field(header.size, sizeof(header.size));
}


void delete_extracted_files() {
    system("find . ! -name '.gitignore' ! -name 'extractor_apple' ! -name 'extractor_x86_64' ! -name 'fuzzer_statement.pdf' ! -name 'main.c' ! -name 'README.md' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'Makefile' ! -name 'success_*' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete > /dev/null 2>&1");
}


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

    fclose(src);
    fclose(dst);
    printf("Archive saved as %s\n", dest);
}

int extract(char* path){
    tests_info.num_of_trials++;
    int rv = 0;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s", path, file_name);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        tests_info.num_of_no_output++;
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***", 30) != 0) {
        goto finally;
    } else {
        tests_info.num_of_success++;
        save_success(tests_info.num_of_success, file_name);
        goto finally;
    }

    finally:
        if(pclose(fp) == -1) {
            printf("Command not found\n");
            rv = -1;
        }
}

int main(int argc, char* argv[]) {
    if (argc < 2) 
    {
        printf("Wrong number of arguments.\n");
        printf("Please provide the path of the extractor as an argument.");
        return -1;
    }
    path_extractor = argv[1];
    file_name = file_name;
    srand(time(NULL));
    

    init_tests_info(&tests_info);
    // Exécuter les tests spécifiques
    name_fuzzing();
    mode_fuzzing();
    size_fuzzing();
        
    delete_extracted_files();

    print_tests(&tests_info);

    return 0;
}
