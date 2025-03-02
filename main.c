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


int num_of_trials = 0;
int num_of_success = 0;
int num_of_no_output = 0;
int num_not_crash_message = 0;

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
    memset(header, 0, sizeof(struct tar_t));
    snprintf(header->name, TAR_NAME_LENGTH, "file_%d.txt", rand() % 1000);
    generate_octal_value(header->mode, sizeof(header->mode), 0777);
    generate_octal_value(header->uid, sizeof(header->uid), 1000);
    generate_octal_value(header->gid, sizeof(header->gid), 1000);
    generate_octal_value(header->size, sizeof(header->size), 1024);
    generate_octal_value(header->mtime, sizeof(header->mtime), 16777216);
    header->typeflag = '0' + (rand() % 8);
    snprintf(header->linkname, sizeof(header->linkname), "link_%d", rand() % 100);
    snprintf(header->uname, sizeof(header->uname), "user_%d", rand() % 100);
    snprintf(header->gname, sizeof(header->gname), "group_%d", rand() % 100);
    strncpy(header->magic, TAR_MAGIC, 6);
    strncpy(header->version, TAR_VERSION, 2);
    calculate_checksum(header);
}

void write_random_tar(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    
    int num_files = 1 + rand() % 5;  // Générer entre 1 et 5 fichiers
    for (int i = 0; i < num_files; i++) {
        struct tar_t header;
        generate_tar_header(&header);
        fwrite(&header, sizeof(struct tar_t), 1, file);
        
        char data[BLOCK_SIZE] = {0};
        fwrite(data, 1, BLOCK_SIZE, file);
    }
    
    char end_block[BLOCK_SIZE * 2] = {0};
    fwrite(end_block, 1, BLOCK_SIZE * 2, file);
    
    fclose(file);
}


void fuzz_field(char *field, size_t field_size, int test_case) { // prend en compte la taille et le type de test avec un pointeur vers le champ à tester 
    memset(field, 0, field_size); // Nettoie tout avant les tests et initialise avec des 0

    switch (test_case) {

        // Test 1 : Champ vide (Copie d'une chaine vide )
        case 1: 
            printf("Test 1: Empty field\n");
            strncpy(field, "", field_size);
            break;

        // Test 2 : Caractères non-ASCII (Ajout de caractère sup à 127 = caractere speciaux nn imprimables et ajout d'un \0 pour assurer que la chaine est bien terminé )
        case 2: 
            printf("Test 2: Non-ASCII field\n");
            for (size_t i = 0; i < field_size - 1; i++) {
                field[i] = 128 + (rand() % 128); 
            }
            field[field_size - 1] = '\0';
            break;

        // Test 3 : Caractères non numériques (Ajout de lettre au hasard pour vérif si c'est pas dans des caractère non numérique)
        case 3: 
            printf("Test 3: Non-numeric field\n");
            for (size_t i = 0; i < field_size - 1; i++) {
                field[i] = 'A' + (rand() % 26); 
            }
            field[field_size - 1] = '\0';
            break;

        // Cas où les tests ne marchent pas 
        default: 
            printf("Invalid test case\n");
            return;
    }

    calculate_checksum(&header); // ça calcule la checksum du header pour verifier si les changements sont bien pris en compte 
}

void name_fuzzing() {
    printf("\n~~~ Name header Fuzzing ~~~\n");
    fuzz_field(header.name, sizeof(header.name), 1);
    fuzz_field(header.name, sizeof(header.name), 2);
    fuzz_field(header.name, sizeof(header.name), 3);
}

void mode_fuzzing() {
    printf("\n~~~ Mode header Fuzzing ~~~\n");
    fuzz_field(header.mode, sizeof(header.mode), 1);
    fuzz_field(header.mode, sizeof(header.mode), 2);
    fuzz_field(header.mode, sizeof(header.mode), 3);
}

void size_fuzzing() {
    printf("\n~~~ Size header Fuzzing ~~~\n");
    fuzz_field(header.size, sizeof(header.size), 1);
    fuzz_field(header.size, sizeof(header.size), 2);
    fuzz_field(header.size, sizeof(header.size), 3);
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

int main(int argc, char* argv[]) {
    if (argc < 2) return -1;

    srand(time(NULL)); //generateur de nombre aleatoire initialisé

    // Exécuter les tests spécifiques
    name_fuzzing();
    mode_fuzzing();
    size_fuzzing();

    const char *tar_file = "archive.tar";
    
    for (int i = 0; i < MAX_TRIES; i++) {
        num_of_trials++;
        write_random_tar(tar_file);

        int rv = 0;
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "%s %s", argv[1], tar_file);
        char buf[33];
        FILE *fp;

        if ((fp = popen(cmd, "r")) == NULL) {
            printf("Error opening pipe!\n");
            return -1;
        }

        if(fgets(buf, 33, fp) == NULL) {
            num_of_no_output++;
            goto finally;
        }
        if(strncmp(buf, "*** The program has crashed ***", 30) != 0) {
            num_not_crash_message++;
            goto finally;
        } else {
            num_of_success++;
            save_success(i+1, tar_file);
            goto finally;
        }

    finally:
        if(pclose(fp) == -1) {
            printf("Command not found\n");
            rv = -1;
        }
        delete_extracted_files();
    }
    delete_extracted_files();

    printf("\nTest status\n");
    printf("Number of trials : %d\n", num_of_trials);
    printf("Number of success: %d\n", num_of_success);
    printf("Number of No output : %d\n", num_of_no_output);
    printf("Number of No crash message: %d\n", num_not_crash_message);

    return 0;
}
