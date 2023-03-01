#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <dir.h>
#include <Windows.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <io.h>
#include "aes.h"


#define Number ((C >= 48) && (C <= 57))
#define notNumber !number
#define whitespace 32
#define backspace 8
#define enter 13
#define Ext ".txt"
#define MAX 50
#define MXCHAR 50
#define lu 186



int DriveLetter;
int Current;
char sys_directory[MAX_PATH];
int last_;
int role_number;
int node_size = 0;


struct role_node{
    char roles_name[50];
    struct role_node * next;
};
struct role_node * root;
struct credentials{
    char first[50];
    char initial[3];
    char last[50];
    char id[7];
    char role[50];
}credentials[50];

struct card{
    char id[7];
    char role[50];
    int status;
    char time_in[50];
    char time_out[50];
}card;

time_t rawtime;
struct tm * timeinfo;

uint8_t key[] = {
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};
uint8_t ciphertext[50][5][AES_BLOCK_SIZE];
uint8_t roundkeys[AES_ROUND_KEY_SIZE];

int CheckID(char ID[]);
void DetectUSB();
void EjectUSB();
void MainMenu();
void PinValidation();
const char* GetUSBPath(char* path, int x);
const char* Get_Time_Date(char arr[]);
void load_credentials(int role_N);
void insert_credentials(char first[], char initial[], char last[], char id[], char role[]);
void load_config();
void newNode_R(struct role_node** head_ref, char * role);
void ChangeStatus();
void process_client();
void get_sysDirectory();
int get_role(char client_role[]);
void print_role();
void load_individual_record(int role_N);
void save_individual_record(int role_N);
int get_update_line(int role);
void update_usb_status();
void dispaly_database();
void securityDec(int opt_role);


size_t convert_hex(uint8_t *dest, size_t count, const char *src);
void readDB(char * filepath, struct credentials * num, int inst);
void condenseString(char * in, char * out, int len);
void dataCondensing(struct credentials * in, struct credentials * out, int member_num);
void data2uint8_t(struct credentials * in, uint8_t out[50][5][16], int member_num);
void getFilePathDB(char * directory, char * nameDb, char * out);
void security(int opt_role, int inst);
int numString(char * in, int inst);



int main(){
    aes_key_schedule_128(key, roundkeys);
    load_config();
    DetectUSB();
}
void DetectUSB(){
    FILE* Card;
    char filepath[100];
    char id[7];
    char role[50];
    int status;
    int x = 0;

    system("cls");
    printf("Please Insert your Flash Drive.");

    do{
        if(x == 25)
            x = 0;

        GetUSBPath(filepath, x);
        Card = fopen(filepath, "r");
        fscanf(Card, "%s %s %d", id, role, &status);
        DriveLetter = x;
        x++;

    }while(Card == NULL);

    strcpy(card.id, id);
    strcpy(card.role, role);
    card.status = status;

    securityDec(get_role(role));
    // load_credentials(get_role(role));
    // dispaly_database();
    // printf("%s %s %d", card.id, card.role, card.status);
    // getch();
    if((CheckID(id)) == 1){
        system("cls"); 
        PinValidation();
    }
    else{
        system("cls");
        printf("Invalid ID\n");
        getch();
        EjectUSB();
        DetectUSB();
    }
}
//Get the FlashDrive path
const char* GetUSBPath(char* path, int x){

    char temp[100] = "";
    temp[0] = x + 'A';
    strcat((strcat(temp,":\\")),"UserID.txt");
    strcpy(path, temp);

    return 0;
}
//Eject Flash Drive
void EjectUSB(){
    FILE* ClientCard;
    char filepath[100];

    do{
        system("cls");
        printf("Please Remove The Flash Drive");
        GetUSBPath(filepath, DriveLetter);
        ClientCard = fopen(filepath, "r");

    }while(ClientCard != NULL);

    fclose(ClientCard);
}
//ID CheckDriveLetter
int CheckID(char ID[]){

    for(int x = 0; x <= last_; x++){
        if((strcmp(ID, credentials[x].id)) == 0){
            Current = x;
            return 1;
            }
    }
    return 0;
}
const char NumberToReturn(){
    char C;

    C = getch();
    if(C == backspace)
        return 0;
    else if(C == enter)
        return 1;
    else if(!(Number))
        return -1;
    return C;
}
//Input Checker
const char* NumberArrToReturn(char string[]){
    char temp;

    for(int x = 0; x < 6; x++){

        temp = NumberToReturn();//Checks the input

        if(temp == 1){//Exit the function
            string[x] = '\0';
            break;
        }
        if(temp == -1 && x >= 0){//Ignores symbols
            if( x >= 0){
                printf("%c", whitespace);
                printf("%c", backspace);
                x--;
            }
        }
        else if(temp == 0){//Delete char
            if(x == 0){
                x--;
            }
            if(x >= 0){
                x--;
                string[x] = '\0';
                printf("%c", backspace);
                printf("%c", whitespace);
                printf("%c", backspace);
                x--;
            }
        }
        else{//copy the temp char to char arry
            string[x] = temp;
            printf("*");
        }
    }
    string[6] = '\0';
    return 0;
}
//Pin Validation
void PinValidation(){
    char PIN[7];
    int count=0;
    int flag=0;

    system("cls");
    //Design Border

    do{
    printf("Please enter your PIN \n");
    printf("PIN: ");
    NumberArrToReturn(PIN);
    if((strcmp(PIN,credentials[Current].id)) == 0){
        count = 0;
        process_client();
    }
    else{
        printf("Try again. Attempt %d \n", count + 1);
        count++;
        }
    }
    while(count > 0 && count < 3 && flag == 0);

    EjectUSB();
}
const char* Get_Time_Date(char arr[]){
    char temp[50];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    //int n = snprintf(temp,sizeof(temp),"[%d:%d_-_%d/%d]", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_mday, timeinfo->tm_mon + 1);
    strftime(temp, sizeof(temp), "%H:%M_-_%d/%m", timeinfo);

    strcpy(arr,temp);

    return 0;
}
void process_client(){
    //char time_in[50], time_out[50];
    char timetemp[50];


    system("cls");
    get_sysDirectory();
    Get_Time_Date(timetemp);

    for(int x = 0; x <= (int)strlen(timetemp); x++){
        if(timetemp[x] == '_')
            printf(" ");
        else
            printf("%c", timetemp[x]);
    }
    if(card.status == 0){
        strcpy(card.time_in, timetemp);

    }
    else{
        strcpy(card.time_out, timetemp);
    }
    //printf("test\n");
    update_usb_status();
    //printf("test\n");
    save_individual_record(get_role(card.role));
    //printf("test\n");
    //getch();
    EjectUSB();
    //printf("test\n");
    DetectUSB();
}
void load_config(){
    FILE* config;
    int size;

    char arr[50];
    char text[50];
    root = NULL;

    if(fopen("config.txt", "r") == NULL){
        printf("configuration file does not exist\n");
        exit(1);
    }
    config = fopen("config.txt", "r");
    fseek (config, 0, SEEK_END);
		size = ftell(config);
		fclose(config);
    if(size == 0){
        printf("configuration file is empty\n");
        exit(1);
    }
    else{
        config = fopen("config.txt", "r");
        while((fgets(arr, sizeof(arr), config)) != NULL){
            sscanf(arr, "%s", text);
            newNode_R(&root, text);
        }
        fclose(config);
    }
}
void newNode_R(struct role_node** head_ref, char * role){
    struct role_node* new_node = (struct role_node*)malloc(sizeof(struct role_node));
    struct role_node* last = *head_ref;

    strcpy(new_node->roles_name, role);
    new_node->next = NULL;

    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }
    while (last->next != NULL)
        last = last->next;

    last->next = new_node;

    return;
}
void get_sysDirectory(){
    char buf[MAX_PATH];
    getcwd(buf,sizeof(buf));
    strcpy(sys_directory, buf);
    //printf("%s", buf);
    //getch();
}
void load_credentials(int role_N){
    FILE* database;
    last_ = -1;
    struct role_node * temp = root;
    char line[200];
    char first[50];
    char initial[3];
    char last[50];
    char id[7];
    char role[50];
    char path[100], filename[MAX_PATH];


    for(int x = 0; x < role_N; x++)
        temp = temp->next;
    strcat(strcpy(filename,"\\"), temp->roles_name);
    strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(filename,"_db.txt"));
    if(fopen(path, "r") == NULL)
            database = fopen(path, "w");
    else{
        memset(credentials, 0, sizeof(credentials));

        database = fopen(path, "r");
        while((fgets(line, sizeof(line), database)) != NULL){
                sscanf(line, "%49[^/]/%49[^/]/%2[^/]/%49[^/]/%6[^/]", last, first, initial, role, id);
                insert_credentials(first, initial, last, id, role);
        }
        fclose(database);
    }


}
void insert_credentials(char first[], char initial[], char last[], char id[], char role[]){



   if(last_ <= 49){
     last_++;
     strncpy(credentials[last_].last, last, strlen(last) + 1);
     strncpy(credentials[last_].first, first, strlen(first) + 1);
     strncpy(credentials[last_].initial, initial, strlen(initial) + 1);
     strncpy(credentials[last_].role, role, strlen(role) + 1);
     strncpy(credentials[last_].id, id, strlen(id) + 1);
  }
}
int get_role(char client_role[]){
    int num_role = -1;
    struct role_node * temp = root;
    while(strcmp(client_role, temp->roles_name) != 0){
        temp = temp->next;
        num_role++;
    }
    return num_role;
}
void print_role(){
    int num_role = -1;
    struct role_node * temp = root;
    while(temp != NULL){
        num_role++;
        printf("[%d] %s\n", num_role, temp->roles_name);
        temp = temp->next;
    }
    role_number = num_role;
}
void load_individual_record(int role_N){
    FILE* individual_record;

    struct role_node * temp = root;
    char line[200], time_in[50], time_out[50];
    char path[100], filename[MAX_PATH];


    for(int x = 0; x < role_N; x++)
        temp = temp->next;
    printf("test");
    strcat(strcpy(filename,"\\"), card.id);
    strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(filename,".txt"));
    if(fopen(path, "r") == NULL)
            individual_record = fopen(path, "w");
    else{

        individual_record = fopen(path, "r");
        while((fgets(line, sizeof(line), individual_record)) != NULL){
            sscanf(line, "%s %s", time_in, time_out);
        }
        fclose(individual_record);
        strcpy(card.time_in, time_in);
        strcpy(card.time_out, time_out);
    }
}
void save_individual_record(int role_N){
    FILE* individual_record;
    FILE* individual_record_temp;

    struct role_node * temp = root;
    char path[MAX_PATH], path_temp[MAX_PATH], filename[MAX_PATH];
    char temp_in[50]; //temp_out[50];
    //int lineNum, count = 0;


    for(int x = 0; x < role_N; x++)
        temp = temp->next;
    fflush(stdin);
    strcat(strcpy(filename,"\\"), card.id);
    strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(filename,".txt"));
    strcat(strcpy(filename,"\\"), card.id);
    strcat(strcat(strcpy(path_temp,"db\\"), temp->roles_name), strcat(filename,".tmp"));
    if(fopen(path, "r") == NULL){
            printf("individual record does not exist, exiting...\n");
            exit(0);
    }
    else{
        if(card.status == 1){
            char buffer[200];

            individual_record = fopen(path, "a");

            individual_record_temp = fopen(path_temp, "r");

            if (individual_record_temp == NULL){
                individual_record_temp = fopen(path_temp, "w");
            exit(EXIT_SUCCESS);
            }
            while ((fgets(buffer, sizeof(buffer), individual_record_temp)) != NULL)
                sscanf(buffer, "%s", temp_in);

            fprintf(individual_record,"%s %s\n", temp_in, card.time_out);
            //printf("%s saving in\n", temp_in);
            //printf("%s saving out\n", card.time_out);
            //getch();
            fclose(individual_record_temp);
            fclose(individual_record);

            remove(path_temp);
            return;
        }
        else{
            individual_record_temp = fopen(path_temp, "w");
            fprintf(individual_record_temp, "%s", card.time_in);
            //printf("%s saving in\n", card.time_in);
            fclose(individual_record_temp);
            return;
        }
    }
}
int get_update_line(int role){
    FILE* individual_record;
    struct role_node * temp = root;
    char temp_in[50], temp_out[50];
    char path[100], filename[MAX_PATH];

    for(int x = 0; x < role; x++)
        temp = temp->next;
    strcat(strcpy(filename,"\\"), card.id);
    strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(filename,".txt"));

    int count = 0;
    individual_record = fopen(path, "r");

    if ( individual_record != NULL ){
        char line[256];
        while (fgets(line, sizeof line, individual_record) != NULL){
            sscanf(line, "%s %s", temp_in, temp_out);
            if (strcmp(temp_out, "0") == 0){
                return count;
                break;
            }
            else
                count++;
        }
        fclose(individual_record);
    }
    return -1;
}
void update_usb_status(){
    FILE* usb_path;

    char path[50];

    GetUSBPath(path, DriveLetter);

    usb_path = fopen(path, "w");
    if(card.status == 0)
        fprintf(usb_path, "%s %s %d", card.id, card.role, 1);
    else
        fprintf(usb_path, "%s %s %d", card.id, card.role, 0);
    fclose(usb_path);
}
void dispaly_database(){
    for(int x = 0; x <= last_; x++)
        printf("%s %s %s %s %s\n", credentials[x].last, credentials[x].first, credentials[x].initial, credentials[x].role, credentials[x].id);
}


void securityDec(int opt_role){

    struct credentials num[50];
    struct credentials num_temp[50];
    struct credentials hex_string[50];

    char fp_temp[200];

    struct role_node * temp = root;

    char filepath[] = "db\\";
    
     getFilePathDB(filepath, temp -> roles_name, fp_temp);
    
      readDB(fp_temp, num, 0);
    
      strcpy(fp_temp, " ");
    
      uint8_t hex_data[50][5][16];
      data2uint8_t(num, hex_data, last_);
    
      for (int i = 0; i <= last_; i++) {
         for (int j = 0; j < 5; j++) {
            aes_decrypt_128(roundkeys, hex_data[i][j], ciphertext[i][j]);
         }
      }
    
    
      for (int i = 0; i <= last_; i++) {
          strcpy(credentials[i].last, (char *)ciphertext[i][0]);
          strcpy(credentials[i].first, (char *)ciphertext[i][1]);
          strcpy(credentials[i].initial, (char *)ciphertext[i][2]);
          strcpy(credentials[i].role, (char *)ciphertext[i][3]);
          strcpy(credentials[i].id, (char *)ciphertext[i][4]);
      }
    
      dataCondensing(credentials, credentials, last_);

}

void dataCondensing(struct credentials * in, struct credentials * out, int member_num){

   int last_len, first_len, middle_len, role_len, id_len;

   for (int i = 0; i <= member_num; i++) {
      last_len   = numString(in[i].last,1);
      //printf("%d\n", last_len);
      first_len  = numString(in[i].first,1);
      //printf("%d\n", first_len);
      middle_len = numString(in[i].initial,1);
      //printf("%d\n", middle_len);
      role_len   = numString(in[i].role,1);
      //printf("%d\n", role_len);
      id_len     = numString(in[i].id,1);
      //printf("%d\n", id_len);

      condenseString(in[i].last,   out[i].last,    last_len);
      condenseString(in[i].first,  out[i].first,   first_len);
      condenseString(in[i].initial, out[i].initial,  middle_len);
      condenseString(in[i].role,   out[i].role,    role_len);
      condenseString(in[i].id,     out[i].id,      id_len);
      //printf("%s\n%s\n%s\n%s\n%s\n\n", out[i].last, out[i].first, out[i].middle, out[i].role, out[i].id);

   }
}

int numString(char * in, int inst){
   int count = 0;

   if(inst == 0){
      for(int j = 0; in[j] != '\0'; j++) {
         count++;
      }
   }
   else if(inst == 1){
      for(int j = 0; in[j] != '#'; j++) {
         count = j + 2;
      }
   }
   return count;
}

void condenseString(char * in, char * out, int len){

   snprintf(out, len, "%s", in);

}
void getFilePathDB(char * directory, char * nameDb, char * out){
   char nameDb_temp[50];

   strcpy(nameDb_temp, nameDb);
   strcpy(out, directory);
   strcat(out, nameDb);
   strcat(out, "\\");

   strcat(out, strcat(nameDb_temp,"_db_enc.txt"));

}
void data2uint8_t(struct credentials * in, uint8_t out[50][5][16], int member_num){

   for (int i = 0; i <= member_num; i++) {
      convert_hex(out[i][0], 16, in[i].last);
      convert_hex(out[i][1], 16, in[i].first);
      convert_hex(out[i][2], 16, in[i].initial);
      convert_hex(out[i][3], 16, in[i].role);
      convert_hex(out[i][4], 16, in[i].id );
   }
}
size_t convert_hex(uint8_t *dest, size_t count, const char *src) {
    char buf[3];
    size_t i;
    for (i = 0; i < count && *src; i++) {
        buf[0] = *src++;
        buf[1] = '\0';
        if (*src) {
            buf[1] = *src++;
            buf[2] = '\0';
        }
        if (sscanf(buf, "%hhx", &dest[i]) != 1)
            break;
    }
    return i;
}
void readDB(char * filepath, struct credentials * num, int inst){
   FILE * database;
   char line[180];
   char last_t[36], first_t[36], middle_t[36], role_t[36], id_t[36];
   last_ = -1;
   // int count = 0;

   if((fopen(filepath, "r") == NULL) && inst == 1){
      database = fopen(filepath, "w");
      // printf("is here\n" );
      fclose(database);
   }


   else {
      database = fopen(filepath, "r");
      while((fgets(line, sizeof(line), database)) != NULL){
         sscanf(line, "%36[^/]/%36[^/]/%36[^/]/%36[^/]/%36[^/]", last_t, first_t, middle_t, role_t, id_t);
        //  fprintf(stderr, "%s test\n", line);
        //  printf("%s\n%s\n%s\n%s\n%s\n\n", last_t, first_t, middle_t, role_t, id_t);
         strcpy(num -> last,      last_t);
         strcpy(num -> first,    first_t);
         strcpy(num -> initial, middle_t);
         strcpy(num -> role,      role_t);
         strcpy(num -> id,          id_t);
         last_++;
         num++;
      }
      fclose(database);
      //fprintf(stderr, "%d\n",);
   }
}