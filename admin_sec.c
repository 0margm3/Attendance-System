#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <windows.h>
#include <dir.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <io.h>

#include "aes.h"

#define Alphabet ((C >= 97 && C <= 122 )|| (C >= 65 && C <= 90))
#define notAlpabet !Alphabet


char sys_directory[MAX_PATH];
int last_;
int role_number;
int DriveLetter;

struct role_node{
   char roles_name[50];
   struct role_node * next;
};

struct deleted_node{
   char roles_name[50];
   struct deleted_node * next;
};

struct credentials{
   char last[33];
   char first[33];
   char initial[33];
   char role[33];
   char id[33];
}credentials[50];

struct role_node * root;
struct deleted_node * root_d;
 

//
//    Admin functions
//
void menu(int opt);
void manage_();
void view_role();
void view_member();
void register_role();
void register_member();
void get_sysDirectory();
void check_folder();
void newNode_R(struct role_node** head_ref, char * role);
void create_config();
void save_config(struct role_node * root);
void load_config();
void save_clear();
int load_clear();
void delete_list(struct role_node** head_ref);
void print_role();
void print_deletedrole();
void printdata();
void insert_credentials(char first[], char  initial[], char last[], char id[], char role[], int opt);
void load_credentials(int role_N);
void save_credentials(int role_N);
void create_individual_record(int role_N);
void load_individual_record(int role_N, int memberNum, int show_);
void delete_role();
void clear_role_folder(int role_N);
void clear_role_database(int role_N);
void delete_member();
void clear_list(struct deleted_node **head_ref);
void delete_individual_record(int role_N, int current_id);
void delete_role_node(struct role_node **head_ref, char rolename[]);
const char* GenerateID(char* id);
bool CheckUniqueID(char userID[]);
void move_node(struct deleted_node **head_refc, char * role_name);
int search_ID();
int checkinputopt(char c[]);
void update_usb_status();
void DetectUSB(char letter);
   void createUserID(char letter);
void EjectUSB();
const char* GetUSBPath(char* path, int x);
void register_usb(char id[], char role[]);
void show_role_member(int role_N, char * role_name);
const char set_drive_letter();

void delay(int milliseconds);

//
// Security functions
//
void updateConfig(char * role_name, int inst);
size_t convert_hex(uint8_t *dest, size_t count, const char *src);
void string2hexString(char* input, char* output);
void readConfig(char * filepath, char * nameDb,int * inst);
void readDB(char * filepath, struct credentials * num, int inst);
void writeDB_enc(char * filepath, uint8_t in[50][5][16], int member_num);
// void writeDB_raw(char * filepath, uint8_t in[50][5][16], int member_num);
int numString(char * in, int inst);
void paddingString(char * in, char * out, int len);
void condenseString(char * in, char * out, int len);
void dataPadding(struct credentials * in, struct credentials * out, int member_num);
void dataCondensing(struct credentials * in, struct credentials * out, int member_num);
void data2HexFormat(struct credentials * in, struct credentials * out, int member_num);
void data2uint8_t(struct credentials * in, uint8_t out[50][5][16], int member_num);
void getFilePathDB(char * directory, char * nameDb, int type, char * out);
void rewriteDBblank(char * file);
void security(int opt_role, int inst);

uint8_t key[] = {
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};
uint8_t ciphertext[50][5][AES_BLOCK_SIZE];
uint8_t roundkeys[AES_ROUND_KEY_SIZE];







int main(int argc, char const *argv[]){
   int deletednode_num;
   root_d = NULL;

   aes_key_schedule_128(key, roundkeys);
   srand(time(NULL));

   get_sysDirectory();
   deletednode_num = load_clear();

   if(deletednode_num > 0){
      for(int x = 0; x < deletednode_num; x++){
         clear_role_database(x);
         clear_role_folder(x);
      }
      clear_list(&root_d);
      save_clear();
      printf("Press any key to continue...");
      getch();
   }
   load_config();
   check_folder();
   menu(0);
}

void get_sysDirectory(){
   char buf[MAX_PATH];
   getcwd(buf,sizeof(buf));
   strcpy(sys_directory, buf);
}

void check_folder(){
   struct role_node * temp = root;
   char path[50];

   DIR* dir = opendir("db");

   if(dir)
      closedir(dir);
   else if(ENOENT == errno)
      mkdir("db");

   while(temp != NULL){
      strcpy(path, "db\\");
      strcat(path, temp->roles_name);
      DIR* dir = opendir(path);

      if(dir)
         closedir(dir);
      else if(ENOENT == errno)
         mkdir(path);

      temp = temp->next;
   }
}

void create_config(int opt){
   char arr[50];
   int x = 0;

   if(opt == 1)
      root = NULL;

   system("cls");
   printf("maximum of 50 characters(use _ as a space):\n");
   do{
      printf("input roles (type done to exit):\n");
      gets(arr);

      if(strcasecmp(arr, "done") == 0)
         break;
      else if(strcasecmp(arr, "") == 0)
         break;
      else{
         newNode_R(&root, arr);
         x++;
      }
   }while(1);

   if(x > 0)
      save_config(root);

   load_config();
}

void save_config(struct role_node * root){
   FILE* config;

   config = fopen("config.txt", "w");
   while(root != NULL){
      fprintf(config, "%s\n", root->roles_name);
      root = root->next;
   }
   fclose(config);

   delete_list(&root);
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

void print_deletedrole(){
   int num_role = -1;
   struct deleted_node * temp = root_d;
   while(temp != NULL){
      num_role++;
      printf("[%d] %s\n", num_role, temp->roles_name);
      temp = temp -> next;
   }
   role_number = num_role;
}

void printdata(){
   for(int x = 0; x <= last_; x++){
      printf("[%d] %s, %s %s. [%s]\n", x + 1, credentials[x].last, credentials[x].first, credentials[x].initial, credentials[x].id);
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

void delete_list(struct role_node** head_ref){

   struct role_node * current = *head_ref;
   struct role_node * next;

   while (current != NULL) {
      next = current->next;
      free(current);
      current = next;
   }

   *head_ref = NULL;
}

void clear_list(struct deleted_node** head_ref){

   struct deleted_node * current = *head_ref;
   struct deleted_node * next;

   while (current != NULL) {
      next = current -> next;
      free(current);
      current = next;
   }

   *head_ref = NULL;
}

void load_config(){
   FILE* config;
   int size;

   char arr[50];
   char text[50];
   root = NULL;

   if(fopen("config.txt", "r") == NULL){
      printf("Config file does not exist\n");
      printf("Create configuration file?(y / n)\n");
      switch(getch()){
         case 'y': create_config(1);  break;
         case 'n': exit(0);          break;
         default: load_config();      break;
      }
   }
   config = fopen("config.txt", "r");
   if (config)
   {
      fseek (config, 0, SEEK_END);
      size = ftell(config);
      fclose(config);
      if(size == 0){
         printf("configuration file is empty\n");
         printf("Create configuration file?(y / n)\n");
         switch(getch()){
            case 'y': create_config(1);  break;
            case 'n': exit(0);          break;
            default: load_config();      break;
         }
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
}

void menu(int opt){

   system("cls");
   printf("MANAGE");
   printf("\n[1] VIEW");
   printf("\n[2] DELETE");
   printf("\n[3] REGISTER");
   printf("\n[4] EXIT\n");
   if(opt == 0)
   opt = getch() - '0';
   switch(opt){
      case 1: system("cls");
      printf("VIEW");
      printf("\n[1] MEMBER");
      printf("\n[2] BACK\n");
      switch(getch() - '0'){
         case 1: view_member(); break;
         case 2: menu(0); break;
         default: menu(1); break;
      }
      break;
      case 2: system("cls");
      printf("DELETE");
      printf("\n[1] MEMBER");
      printf("\n[2] ROLE");
      printf("\n[3] BACK\n");
      switch(getch() - '0'){
         case 1: delete_member(); break;
         case 2: delete_role(); break;
         case 3: menu(0); break;
         default: menu(2); break;
      }
      break;
      case 3: system("cls");
      printf("REGISTER");
      printf("\n[1] MEMBER");
      printf("\n[2] ROLE");
      printf("\n[3] BACK\n");
      switch(getch() - '0'){
         case 1: register_member(); break;
         case 2: register_role(); break;
         case 3: menu(0); break;
         default: menu(3); break;
      }
      break;
      case 4:
      save_config(root);
      save_clear();
      exit(0);
      break;
      default: menu(0);        break;
   }
}

void register_role(){
   create_config(0);
   save_config(root);
   check_folder();
   menu(0);
}

void register_member(){
   int opt_role;
   char opt[3];
   char letter;
   struct role_node * temp = root;
   char temp_fn[32];
   char temp_ln[32];
   char temp_mi[32];
   char user_ID[32];
   char temp_rl[32];
   char line[120];

   system("cls");
   printf("Choose role\n");
   print_role();
   printf("[%d] BACK\n", role_number + 1);
   scanf("%s", opt);



   if(checkinputopt(opt) == -1)
      menu(3);
   else {
      opt_role = checkinputopt(opt);
      GenerateID(user_ID);
      if(opt_role < 1 && opt_role > role_number)
         menu(3);
      else{
         if(opt_role == role_number + 1)
            menu(3);
         // load_credentials(opt_role);
         security(opt_role, 1);
         temp = root;
         for(int x = 0; x < opt_role; x++){
            temp = temp->next;
         }
      }

      fflush(stdin);
      strcpy(temp_rl, temp->roles_name);
      printf("Maximum of 32 characters / per name\n");
      printf("Format: Last Name/First Name/Middle Name\n");
      printf("Example: Gerardo/Omar/Aabet\n");
      printf("Input full name: ");
      gets(line);
      sscanf(line, "%32[^/]/%32[^/]/%32[^/]", temp_ln, temp_fn, temp_mi);
      insert_credentials(temp_fn, temp_mi, temp_ln, user_ID, temp_rl, 0);
      // printdata();
      // getch();
      // save_credentials(opt_role);
      security(opt_role, 0);
      create_individual_record(opt_role);
      printf("INSERT USB FLASH DRIVE\n");
      printf("input user flash driver letter(A - Z): ");
      //letter = set_drive_letter();
      do{
         letter = set_drive_letter();
      }while(letter == -1);
      printf("%c", letter);
      DetectUSB(letter);
      register_usb(user_ID, temp->roles_name);
      EjectUSB();
      menu(3);
   }
}

const char* GenerateID(char* GenerateID_STR_ID){
   int GenerateID_int_temp;
   bool reGeneratedID;

   for(int x = 0; x < 6; x++)
   {
      GenerateID_int_temp = rand() % 10;
      GenerateID_STR_ID[x] = GenerateID_int_temp + '0';
   }
   GenerateID_STR_ID[6] = '\0';

   reGeneratedID = CheckUniqueID(GenerateID_STR_ID);

   if(reGeneratedID == TRUE)
   GenerateID(GenerateID_STR_ID);

   return 0;
}

bool CheckUniqueID(char userID[]){
   int temp;

   for(int x = 0; x <= last_; x++)
   {
      temp = strcmp(userID, credentials[x].id);
      if(temp == 0)
      return true;
   }
   return false;
}

void insert_credentials(char first[], char initial[], char last[], char id[], char role[], int opt){

   if(last_ <= 49){
      last_++;
      strncpy(credentials[last_].last, last, strlen(last) + 1);
      strncpy(credentials[last_].first, first, strlen(first) + 1);
      strncpy(credentials[last_].initial, initial, strlen(initial) + 1);
      strncpy(credentials[last_].role, role, strlen(role) + 1);
      strncpy(credentials[last_].id, id, strlen(id) + 1);
      // printf("insert - %s\n", last);
      // printf("insert - %d\n", last_);
      // getch();
   }
   else{
      printf("Full.");
      menu(0);
   }
}

void load_credentials(int role_N){
   FILE* database;
   last_ = -1;
   struct role_node * temp = root;
   char line[200];
   char first[33];
   char initial[33];
   char last[33];
   char id[33];
   char role[33];
   char path[100], filename[MAX_PATH];
   int opt = 3; //read it as is

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
         sscanf(line, "%32[^/]/%32[^/]/%32[^/]/%32[^/]/%32[^/]", last, first, initial, role, id);
         insert_credentials(first, initial, last, id, role, opt);
      }

      fclose(database);
   }
   //delay(1000);
   //rewriteDBblank(path);
}

void save_credentials(int role_N){
   FILE* database;
   struct role_node * temp = root;
   char path[200], filename[MAX_PATH];

   for(int x = 0; x < role_N; x++)
      temp = temp->next;

   strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(strcat(strcpy(filename,"\\"), temp->roles_name),"_db.txt"));

   database = fopen(path, "w");

   for(int x = 0; x <= last_; x++)
      fprintf(database, "%s/%s/%s/%s/%s\n", credentials[x].last, credentials[x].first, credentials[x].initial, credentials[x].role, credentials[x].id);

   fclose(database);

   //secDB(temp->roles_name, 0);
   //updateConfig(temp->roles_name, 0);
   //rewriteDBblank(path);
}

void updateConfig(char * role_name, int inst){
   FILE * config;

   config = fopen("sec\\config.txt", "w");
   fprintf(config, "..\\\\db\\\\/%s/%d", role_name, inst);

   fclose(config);
}

void create_individual_record(int role_N){
   FILE* client_file;
   struct role_node * temp = root;
   char path[200], filename[20];

   for(int x = 0; x < role_N; x++)
   temp = temp->next;

   strcat(strcpy(filename, credentials[last_].id), ".txt");
   strcpy(path, sys_directory);
   strcat(strcat(strcat(strcpy(path,"db\\"), temp->roles_name), "\\"), filename);


   if(fopen(path, "r") == NULL){
      client_file = fopen(path, "w");
      fclose(client_file);
   }
}

void delete_member(){
   int opt_role;
   char opt[3];
   int current;
   struct role_node * temp = root;

   system("cls");
   printf("SELECT ROLE\n");
   print_role();
   printf("[%d] BACK\n", role_number + 1);
   scanf("%s", opt);
   fflush(stdin);

   if(checkinputopt(opt) == -1)
      menu(3);

   else
      opt_role = checkinputopt(opt);

   if(opt_role < 1 && opt_role > role_number)
      menu(0);

   else{
      if(opt_role == role_number + 1)
      menu(2);
      else{
         temp = root;
         for(int x = 1; x < opt_role; x++)
         temp = temp->next;

         // Add security here
         security(opt_role, 1);
         // load_credentials(opt_role);

      }
   }
   if(last_ == -1){
      printf("empty\n");
      getch();
      menu(0);
   }
   printdata();

   current = getch() - '0';

   delete_individual_record(opt_role, current - 1);

   for(int x = current; x <= last_; x++){
      strncpy(credentials[x].last, credentials[x + 1].last, strlen(credentials[x + 1].last));
      strncpy(credentials[x].first, credentials[x + 1].first, strlen(credentials[x + 1].first));
      strncpy(credentials[x].initial, credentials[x + 1].initial, strlen(credentials[x + 1].initial));
      strncpy(credentials[x].role, credentials[x + 1].role, strlen(credentials[x + 1].role));
      strncpy(credentials[x].id, credentials[x + 1].id, strlen(credentials[x + 1].id));
   }

   last_--;
   security(opt_role, 0);
   menu(2);

}

void delete_individual_record(int role_N, int current_id){
   struct role_node * temp = root;
   char path[200], foldername[50], filename[MAX_PATH];

   // load_credentials(role_N);


   if(current_id == -1){
      for(int x = 0; x < role_N; x++)
      temp = temp->next;
      if(last_ == -1)
      return;
      strcpy(foldername, temp->roles_name);
      for(int x = 0; x <= last_; x++){
         strcpy(path, sys_directory);
         strcat(strcat(strcat(strcat(path,"\\db\\"), foldername), "\\"), strcat(strcpy(filename, credentials[x].id), ".txt"));
         //printf("%s\n", path);

         if (remove(path) == 0)
         printf("%s deleted\n", filename);
         else
         printf("%s %s\n", filename , strerror(errno));

      }
   }
   else{
      for(int x = 0; x < role_N; x++)
      temp = temp->next;
      strcpy(path, sys_directory);
      strcat(strcpy(filename, credentials[current_id].id), ".txt");
      strcat(strcat(strcat(strcat(path,"db\\"), temp->roles_name), "\\"), filename);
      if (remove(path) == 0)
      printf("Deleted successfully\n");
      else
      printf("Unable to delete the file\n");
      return;
   }
}

void delete_role(){
   int opt_role;
   char opt[3];
   struct role_node * temp = root;

   system("cls");
   printf("SELECT ROLE\n");
   print_role();
   printf("[%d] BACK\n", role_number + 1);
   scanf("%s", opt);
   fflush(stdin);


   if( checkinputopt(opt) == -1)
   menu(2);
   else {
      opt_role = checkinputopt(opt);
      printf("%d %d\n", opt_role, role_number);
      getch();
      if(opt_role < 1 && opt_role > role_number)
         delete_member();
      else{
         if(opt_role == role_number + 2)
            menu(2);
         else{
            temp = root;
            for(int x = 1; x < opt_role; x++)
            temp = temp->next;
         }
      }
   }
   delete_individual_record(opt_role, -1);
   move_node(&root_d, temp->roles_name);
   delete_role_node(&root, temp->roles_name);
   //print_deletedrole();
   //getch();
   //save_config(root);
   //save_clear();
   menu(2);
}

void clear_role_database(int role_N){
   struct deleted_node * temp = root_d;
   char path[200], foldername[50], filename[MAX_PATH];

   for(int x = 0; x < role_N; x++)
   temp = temp -> next;
   strcpy(foldername, temp->roles_name);

   strcpy(path, sys_directory);
   strcat(strcat(strcat(strcat(path,"\\db\\"), foldername), "\\"), strcat(strcpy(filename, foldername),"_db.txt"));
   printf("%s\n", path);

   if (_unlink(path) == 0)
      printf("%s deleted\n", filename);
   else
      printf("%s\n", strerror(errno));
}

void clear_role_folder(int role_N){

   struct deleted_node * temp = root_d;
   char path[200], foldername[50];

   for(int x = 0; x < role_N; x++)
   temp = temp->next;
   strcpy(foldername, temp->roles_name);

   strcpy(path, sys_directory);
   strcat(strcat(path,"\\db\\"), foldername);
   printf("%s\n", path);

   int status = unlink(path);
   if (rmdir(path) == 0)
      printf("%s deleted\n", foldername);
   else
      printf("%d - %s\n", status, strerror(errno));

}

void delete_role_node(struct role_node **head_ref, char rolename[]){
   struct role_node* temp = *head_ref, *prev;

   if (temp != NULL && strcmp(temp->roles_name, rolename) == 0){
      *head_ref = temp->next;   // Changed head
      free(temp);               // free old head
      return;
   }

   while (temp != NULL && strcmp(temp->roles_name, rolename) != 0){
      prev = temp;
      temp = temp->next;
   }

   if (temp == NULL) return;

   prev->next = temp->next;

   free(temp);  // Free memory

   return;
}

void move_node(struct deleted_node** head_ref, char * role_name){
   struct deleted_node* new_node = (struct deleted_node*)malloc(sizeof(struct deleted_node));
   struct deleted_node* last = *head_ref;
   char temp[50];

   strcpy(temp, role_name);
   strcpy(new_node->roles_name, temp);
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

void save_clear(){
   FILE* clear;

   clear = fopen("clear.txt", "w");
   while(root_d != NULL){
      fprintf(clear, "%s\n", root_d->roles_name);
      root_d = root_d->next;
   }
   fclose(clear);
}

int load_clear(){
   FILE* clear;
   int size;

   char arr[50];
   char text[50];
   int node_num = 0;

   if(fopen("clear.txt", "r") == NULL){
      return -1;
   }
   clear = fopen("clear.txt", "r");
   if (clear){
      fseek (clear, 0, SEEK_END);
      size = ftell(clear);
      fclose(clear);
      if(size == 0){
         return -1;
      }
      else{
         clear = fopen("clear.txt", "r");
         while((fgets(arr, sizeof(arr), clear)) != NULL){
            sscanf(arr, "%s", text);
            move_node(&root_d, text);
            node_num++;
         }
         fclose(clear);
      }
      return node_num;
   }
   return 0;
}

int checkinputopt(char c[]){
   int temp[3];
   int i, k = 0;


   for(int x = 0; x < 2; x++)
   temp[x] = c[x] - '0';
   for(int x = 0; x <  (int)strlen(c); x++){
      if(!(temp[x] >= 0 && temp[x] <= 9))
         return -1;
   }
   if(strlen(c) < 2)
      return temp[0] * 1;

   for (i = 0; i < 2; i++)
      k = 10 * k + temp[i];
   return k;

}

void createUserID(char letter){
   FILE* Card;
   char filepath[100];

   DriveLetter = letter - 'A';
   GetUSBPath(filepath, DriveLetter);
   printf("%s\n", filepath);
   Card = fopen(filepath, "w");
   fclose(Card);
}

void DetectUSB(char letter){
   FILE* Card;
   char filepath[100];

   DriveLetter = letter - 'A';
   GetUSBPath(filepath, DriveLetter);
   //printf("%s\n", filepath);
   do{
      Card = fopen(filepath, "r");
   }while(Card == NULL);
}

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

void register_usb(char id[], char role[]){
   FILE* usb_path;

   char path[50];

   GetUSBPath(path, DriveLetter);

   usb_path = fopen(path, "w");
   fprintf(usb_path, "%s %s %d", id, role, 0);
   fclose(usb_path);
}

const char set_drive_letter(){
   char UpperCase[27] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','\0'};
   char LowerCase[27] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','\0'};
   char C;
   C = getch();

   if(notAlpabet)
      return -1;
   else if(Alphabet){
      for(int x = 0; x < 27; x++){
         if(C == LowerCase[x] || C == UpperCase[x])
            C = UpperCase[x];
      }
   }
   return C;
}

void view_member(){
   int opt_role;
   char opt[3];

   struct role_node * temp = root;

   system("cls");
   printf("Choose role\n");
   print_role();
   printf("[%d] BACK\n", role_number + 1);
   scanf("%s", opt);

   if(checkinputopt(opt) == -1)
      menu(1);
   else
      opt_role = checkinputopt(opt);

   if(opt_role < 1 && opt_role > role_number)
      menu(1);
   else{

      for(int x = 0; x < opt_role; x++){
         temp = temp->next;
      }


      if(opt_role == role_number + 1)
         menu(1);

      temp = root;
      for(int x = 0; x < opt_role; x++){
         temp = temp->next;
      }

      // load_credentials(opt_role);

   }
   show_role_member(opt_role, temp -> roles_name);
}

void show_role_member(int role_N, char * role_name){
   char temp_opt[3];
   int opt, line;

   // add security here!
   //load_credentials(role_N);
   security(role_N, 1);

   system("cls");
   printf("LIST OF MEMBER: \n");
   printdata();
   printf("SELECT MEMBER(0 - GO BACK): ");
   scanf("%s", temp_opt);
   opt = checkinputopt(temp_opt);

   if(opt == 0)
      menu(1);
   if(opt > last_ + 1 || opt < 0){
      printf("Invalid member!\n");
      printf("Press any key to go back to menu");
      getch();
      menu(1);
   }

   printf("HOW MANY LINES TO SHOW(0 = ALL): ");
   scanf("%s", temp_opt);
   line = checkinputopt(temp_opt);
   system("cls");
   printf("[%s] %s, %s %s.", credentials[opt - 1].id, credentials[opt - 1].last, credentials[opt - 1].first, credentials[opt - 1].initial);
   load_individual_record(role_N, opt, line);
   printf("Press any key go back...");
   getch();
   view_member();
}

void load_individual_record(int role_N, int memberNum, int show_){
   FILE* individual_record;

   struct role_node * temp = root;
   char line[200], time_in[50], time_out[50];
   char path[100], filename[MAX_PATH], chr;
   int count_lines = 0, iteration = 0;
   bool show_all;

   for(int x = 0; x < role_N; x++)
   temp = temp->next;

   strcat(strcpy(filename,"\\"), credentials[memberNum - 1].id);
   //printf("%s", credentials[memberNum - 1].id);
   strcat(strcat(strcpy(path,"db\\"), temp->roles_name), strcat(filename,".txt"));
   printf("\n");
   individual_record = fopen(path, "r");
   //extract character from file and store in chr
   chr = getc(individual_record);
   while (chr != EOF)
   {
      if (chr == '\n')
         count_lines = count_lines + 1;

      chr = getc(individual_record);
   }
   fclose(individual_record); //close file.

   if(show_ >= count_lines || show_ == 0)
      show_all = true;
   else
      show_all = false;

   printf("[time in]\t\t[time out]\n");
   individual_record = fopen(path, "r");
   while((fgets(line, sizeof(line), individual_record)) != NULL){

      sscanf(line, "%s %s", time_in, time_out);
      for(int x = 0; x < (int)strlen(time_in); x++){
         if(time_in[x] == '_')
            time_in[x] = ' ';
         if(time_out[x] == '_')
            time_out[x] = ' ';
      }
      if(show_all == true)
         printf("%s\t\t%s\n", time_in, time_out);

      else if(iteration >= count_lines - show_ && show_all == false)
         printf("%s\t\t%s\n", time_in, time_out);

      iteration++;
   }
   fclose(individual_record);
}

void delay(int milliseconds){
    long pause;
    clock_t now,then;

    pause = milliseconds*(CLOCKS_PER_SEC/1000);
    now = then = clock();
    while( (now-then) < pause )
        now = clock();
}

void rewriteDBblank(char * file){
   FILE * file_f;

   file_f = fopen(file, "w");
   fprintf(file_f, " ");
   fclose(file_f);
}

void security(int opt_role, int inst){

   struct credentials num[50];
   struct credentials num_temp[50];
   struct credentials hex_string[50];

   char fp_temp[200];

   struct role_node * temp = root;

   for(int x = 0; x < opt_role; x++)
      temp = temp->next;

   char filepath[] = "db\\";

   if(inst == 0){

      dataPadding(credentials, num_temp, last_);

      // for(int x = 0; x <= last_; x++){
      //    printf("[%d] %s, %s %s. [%s]\n", x + 1, credentials[x].last, credentials[x].first, credentials[x].initial, credentials[x].id);
      // }

      data2HexFormat(num_temp, hex_string, last_);
      uint8_t hex_data[50][5][16];
      data2uint8_t(hex_string, hex_data, last_);

      //inst = 1;
      for (int i = 0; i <= last_; i++) {
         for (int j = 0; j < 5; j++) {
            aes_encrypt_128(roundkeys, hex_data[i][j], ciphertext[i][j]);
         }
      }

      strcpy(fp_temp, " ");
      getFilePathDB(filepath, temp -> roles_name, 0, fp_temp);
      writeDB_enc(fp_temp, ciphertext, last_);

   }
   else if(inst == 1){

      getFilePathDB(filepath, temp -> roles_name, inst, fp_temp);

      readDB(fp_temp, num, inst);

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
         //fprintf(stderr, "%s test\n", line);
         //printf("%s\n%s\n%s\n%s\n%s\n\n", last_t, first_t, middle_t, role_t, id_t);
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

void getFilePathDB(char * directory, char * nameDb, int type, char * out){
   char nameDb_temp[50];

   strcpy(nameDb_temp, nameDb);
   strcpy(out, directory);
   strcat(out, nameDb);
   strcat(out, "\\");

   strcat(out, strcat(nameDb_temp,"_db_enc.txt"));

}

void dataPadding(struct credentials * in, struct credentials * out, int member_num){

   int last_len, first_len, middle_len, role_len, id_len;

   for (int i = 0; i <= member_num; i++) {
      last_len   = numString(in[i].last,0);
      //printf("%d\n", last_len);
      first_len  = numString(in[i].first,0);
      //printf("%d\n", first_len);
      middle_len = numString(in[i].initial,0);
      //printf("%d\n", middle_len);
      role_len   = numString(in[i].role,0);
      //printf("%d\n", role_len);
      id_len     = numString(in[i].id,0);
      //printf("%d\n", id_len);

      paddingString(in[i].last,   out[i].last,    last_len);
      paddingString(in[i].first,  out[i].first,   first_len);
      paddingString(in[i].initial, out[i].initial,  middle_len);
      paddingString(in[i].role,   out[i].role,    role_len);
      paddingString(in[i].id,     out[i].id,      id_len);
      //printf("%s\n%s\n%s\n%s\n%s\n\n", out[i].last, out[i].first, out[i].initial, out[i].role, out[i].id);
   }
}

void paddingString(char * in, char * out, int len){

   strcpy(out, in);

   //printf("%d\n", 16 - len - 1);

   for (int i = 0; (int)i <= 16 - len - 1; i++) {
      strcat(out, "#");
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

void condenseString(char * in, char * out, int len){

   snprintf(out, len, "%s", in);

}

void data2HexFormat(struct credentials * in, struct credentials * out, int member_num){

   for (int i = 0; i <= member_num; i++) {
      string2hexString(in[i].last,    out[i].last);
      string2hexString(in[i].first,   out[i].first);
      string2hexString(in[i].initial, out[i].initial);
      string2hexString(in[i].role,    out[i].role);
      string2hexString(in[i].id,      out[i].id);
      //printf("%s\n%s\n%s\n%s\n%s\n\n", out[i].last, out[i].first, out[i].middle, out[i].role, out[i].id);
   }
}

void string2hexString(char* input, char* output){
    int loop;
    int i;

    i=0;
    loop=0;

    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }
    output[i++] = '\0';
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

void writeDB_enc(char * filepath, uint8_t in[50][5][16], int member_num){
   FILE * database;

   //printf("%s\n", filepath);
   database = fopen(filepath, "w");
   for (int i = 0; i <= member_num; i++) {
      for (int j = 0; j < 5; j++) {
         for (int k = 0; k < 16; k++) {
            fprintf(database, "%2x", in[i][j][k]);
         }
         fprintf(database,"/");
      }
      fprintf(database,"\n");
   }
   fclose(database);
}

//
