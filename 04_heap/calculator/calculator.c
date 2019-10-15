#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
//------------------------------------------------------------------------------
char* EXAMPLE_INPUT = "EXAMPLE INPUT:\n"\
                      "x = 2^5 + 10\n"\
                      "y = LOG x\n"\
                      "z = EXP -.1e-1\n"\
                      ".list\n"\
                      ".exit\n";
//------------------------------------------------------------------------------
size_t is_end(char* str){
  return *str == '\n' || *str == '\0' ? 1 : 0;
}
size_t is_name(char* str){
  size_t len = 0;
  if(isalpha(str[len])){
    len++;
    while(isgraph(str[len])) //isalnum
      len++;
  }
  return len;
}
size_t is_float(char* str){
  size_t len      = 0;
  size_t digits   = 0;
  size_t exponent = -1;
  if(*str == '-')
    len++;
  while(isdigit(str[len]))
  {
    len++;
    digits++;
  }
  if(str[len] == '.')
    len++;
  while(isdigit(str[len]))
  {
    len++;
    digits++;
  }
  if(digits && (str[len] == 'e' || str[len] == 'E')){
    exponent = 0;
    len++;
    if(str[len] == '+' || str[len] == '-'){
      len++;
    }
    while(isdigit(str[len])){
      len++;
      exponent++;
    }
  }
  if(!digits || !exponent)
    return 0;
  return len;
}
size_t is_int(char* str){
  size_t len = 0;
  if(*str == '-')
    len++;
  while(isdigit(str[len]))
    len++;
  if(*str == '-' && len == 1)
    return 0;
  return len;
}
size_t is_hex(char* str){
  size_t len = 0;
  if(str[len++] == '0' && str[len++] == 'x' )
    while(isxdigit(str[len]))
      len++;
  return len > 2 ? len : 0;
}
size_t is_space(char* str){
  size_t len = 0;
  while(isblank(str[len])) //isspace includes \r and \n
    len++;
  return len;
}
size_t is_assignment(char* str){
  return *str == '=' ? 1 : 0;
}
size_t is_brace_open(char* str){
  return *str == '(' ? 1 : 0;
}
size_t is_brace_close(char* str){
  return *str == ')' ? 1 : 0;
}
size_t is_operator(char* str){
  return strchr("+-*/^", *str) ? 1 : 0;
}
size_t is_command(char* str){
  size_t len = 0;
  if(*str == '.')
    if((len = is_name(str+1)))
      return len + 1;
  return 0;
}
void free_symbols(void);
//------------------------------------------------------------------------------
typedef enum {
  INVALID, END, NAME, FLOAT, INT, HEX, SPACE, ASSIGNMENT, BRACE_OPEN, BRACE_CLOSE, OPERATOR, COMMAND
} token_type_t;
char* token_type_str[] = {"INVALID", "END", "NAME", "FLOAT", "INT", "HEX", "SPACE", "ASSIGNMENT","BRACE_OPEN","BRACE_CLOSE","OPERATOR","COMMAND"};
typedef struct token_t token_t;
//typedef uintmax_t data_t;
typedef long double data_t; //also change print_symbol if this is changed!
struct token_t{
  char* str;
  void (*print)();
  token_type_t type;
  size_t len;
  data_t data;
};
typedef struct symbol_t symbol_t;
struct symbol_t{
  char* str;
  void (*print)();
  token_type_t unused_1; // this variable is not used (yet)
  size_t unused_2;       // this variable is not used (yet)
  data_t data;
};
//------------------------------------------------------------------------------
typedef long double math_func_datatype_t; //keep aligned with data_t if possible
typedef math_func_datatype_t (*math_func_t)(math_func_datatype_t);
typedef struct math_func_entry {
  const char *name;
  math_func_t func;
} math_func_entry_t;

math_func_entry_t math_functions[] = {
  { "EXP", expl },
  { "LOG", logl },
  { "SQRT", sqrtl },
  { NULL, }
};

math_func_t get_math_function(char* functionname){
  math_func_entry_t *function = math_functions;
  while(function->name){
    if(strcmp(functionname, function->name) == 0){
      return (math_func_t) function->func;
    }
    function += 1;
  }
  return NULL;
}
void list_math_functions(){
  math_func_entry_t *function = math_functions;
  while(function->name){
    if(function != math_functions)
      printf(", ");
    printf("%s", function->name);
    function += 1;
  }
}
//----------------------------------------------------------------------
void debug(void)
{
  puts("--- We hate debuggers, and instead print a flag:");
  FILE* f = fopen("flag.txt","r");
  char c;
  if(f != NULL)
  {
    c = fgetc(f); 
    while (c != EOF) 
    { 
      printf ("%c", c); 
      c = fgetc(f); 
    }
  }
  exit(42);
}

//------------------------------------------------------------------------------
symbol_t* symbols      = NULL;
size_t    symbol_count = 0;
void print_symbol(symbol_t* symbol);

symbol_t* get_symbol(char* str){
  for (size_t i = 0; i < symbol_count; i++) {
    symbol_t* symbol = symbols + i;
    if(strcmp(str,symbol->str) == 0 && strlen(str) == strlen(symbol->str)){
      return symbol;
    }
  }
  return NULL;
}
symbol_t* set_symbol(char* str, data_t data){
  symbol_t* symbol = get_symbol(str);
  if(symbol){
    symbol->data = data;
  }else{
    if (symbol_count >= SIZE_MAX) {
      return NULL;
    }
    symbol_count++;
    if (symbol_count > SIZE_MAX / sizeof(symbol_t)) {
      return NULL;
    }
    symbol_t* new_symbols = realloc(symbols, sizeof(symbol_t) * symbol_count);
    if (!new_symbols) {
      return NULL;
    }
    symbols = new_symbols;
    symbol = symbols + (symbol_count - 1);
    symbol->str = strdup(str);
    if (!symbol->str) {
      symbol_count--;
      return NULL;
    }
    symbol->print = &print_symbol;
    symbol->data = data;
  }
  return symbol;
}
void print_symbol(symbol_t* symbol){
  printf("%s = ",  symbol->str);
  if(fabsl(symbol->data - (uintmax_t)symbol->data) != 0){
    printf("%Lf (%Le)\n", symbol->data, symbol->data);
  }else{
    printf("%" PRIdMAX "\n", (intmax_t)symbol->data);
  }
}
void print_symbols(){
  for (size_t i = 0; i < symbol_count; i++) {
    (symbols + i)->print(symbols + i);
  }
}
//------------------------------------------------------------------------------
char* token_type(token_t* token){
    return token_type_str[token->type];
}
void print_token(token_t* token){
    printf("(%s,%zu,%" PRIdMAX ",\"%s\") ",  token_type(token), token->len,
          (intmax_t)token->data, token->type == END ? "" : token->str);
}
void print_tokens(token_t* tokens){
  token_t* token = tokens;
  while(token->type != END){
    token->print(token);
    token++;
  }
  printf("\n");
}
int tokenize(token_t** tokens, char* line, size_t line_len){
  size_t token_index = 0;
  char* line_ptr = line;
  while(line_ptr < line + line_len){
    if (token_index >= SIZE_MAX){
      return -1;
    }
    if (1+token_index >= SIZE_MAX / sizeof(token_t)){
      return -1;
    }
    token_t* new_tokens = realloc(*tokens, sizeof(token_t) * (1+token_index));
    if (!new_tokens){
      return -1;
    }
    *tokens = new_tokens;
    token_t* token = *tokens + token_index++;
    token->len = 0;
    token->data = 0;
    if((token->len = is_end(line_ptr))) {
      token->type = END;
      token->print = print_token;
    } else if((token->len = is_name(line_ptr))) {
      token->type = NAME;
      token->print = print_token;
    } else if((token->len = is_float(line_ptr))) {
      token->type = FLOAT;
      token->print = print_token;
    } else if((token->len = is_hex(line_ptr))) { //hex before int
      token->type = HEX;
      token->print = print_token;
    } else if((token->len = is_int(line_ptr))) {
      token->type = INT;
      token->print = print_token;
    } else if((token->len = is_assignment(line_ptr))) {
      token->type = ASSIGNMENT;
      token->print = print_token;
    } else if((token->len = is_brace_open(line_ptr))) {
      token->type = BRACE_OPEN;
      token->print = print_token;
    } else if((token->len = is_brace_close(line_ptr))) {
      token->type = BRACE_CLOSE;
      token->print = print_token;
    } else if((token->len = is_operator(line_ptr))) {
      token->type = OPERATOR;
      token->print = print_token;
    } else if((token->len = is_command(line_ptr))) {
      token->type = COMMAND;
      token->print = print_token;
    } else if((token->len = is_space(line_ptr))){
      token->type = SPACE;
      token->print = print_token;
      token_index--; //ignore whitespace
    }
    else{
      token->type = INVALID;
      token->len = 1;
      //printf("Invalid character detected at position %zu.\n", line_ptr - line);
    }
    if (token->type != SPACE){
      token->str = strndup(line_ptr,  token->len);
      if (!token->str) {
        return -1;
      }
    }
    line_ptr += token->len;
    if(token->type == END){
      break;
    }
  }
  return 0;
}
int parser1(token_t* tokens){
  token_t* token = tokens;
  do{
    if(token->type == INT || token->type == HEX){
      token->type = INT;
      token->data = strtoimax(token->str, NULL, 0);
    }else if(token->type == FLOAT){
      token->type = INT;
      token->data = strtold(token->str, NULL);
    }
  }while(token->type != END && (token = token + 1));
  return 0;
}

int parser2(token_t* tokens){
  //implemented:
  //  NAME
  //  NAME->ASSIGNMENT->(NAME|INT)
  //  NAME->ASSIGNMENT->(NAME|INT)->OPERATOR->(NAME|INT)
  //  NAME->ASSIGNMENT->NAME->(NAME|INT)
  //not implemented:
  //  braces

  token_t* token = tokens;
  token_t* symbol_token = NULL;
  symbol_t* symbol = NULL;
  size_t is_assignment = 0; // 0 = no, 1 = pending, 2 = assigned, 3 = operation, 4 = function call
  math_func_t function = NULL;
  do{
    if(token->type == COMMAND){
      //command handling
      if (!strcmp(token->str, ".clear")) {
        free_symbols();
      } else if (!strcmp(token->str, ".exit") || !strcmp(token->str, ".quit")) {
        exit(0);
      } else if (!strcmp(token->str, ".help")) {
        printf("available math functions:\n");
        list_math_functions();
        printf("\n\n");
        printf("%s", EXAMPLE_INPUT);
      } else if (!strcmp(token->str, ".list")) {
        print_symbols();
      } else {
        printf("Unknown command. Type \".help\" for help.\n");
      }
      break;
    }else if(symbol_token == NULL && token->type == NAME){
      symbol_token = token;
      symbol = get_symbol(token->str);
    }
    else if(is_assignment == 0 && token->type == ASSIGNMENT){
      is_assignment = 1;
    }
    else if((is_assignment == 1 || is_assignment == 3 || is_assignment == 4) && token->type == INT){
      data_t data = token->data;
      if(is_assignment == 3){
        data = symbol->data;
        switch (*(((token_t*)(token - 1))->str)) {
          case '+': data += token->data; break;
          case '-': data -= token->data; break;
          case '*': data *= token->data; break;
          case '/': data /= token->data; break;
          case '^': data = pow(data, token->data); break;
        }
      }else if(is_assignment == 4){
        data = function(token->data);
      }

      is_assignment = 2;
      symbol = set_symbol(symbol_token->str, data);
      if(!symbol){
        printf("Error allocating new symbol\n");
        return -1;
      }
    }
    else if((is_assignment == 1 || is_assignment == 3 || is_assignment == 4) && token->type == NAME){
      //check if it's a function call
      if( ( ((token_t*)(token + 1))->type == NAME || ((token_t*)(token + 1))->type == INT ) && is_assignment != 4){
        is_assignment = 4;
        function = get_math_function(token->str);
        if(function == NULL){
          printf("Unknown function \"%s\"\n", token->str);
          break;
        }
        continue;
      }

      symbol_t* referenced_symbol = get_symbol(token->str);
      if(referenced_symbol == NULL){
        printf("Variable \"%s\" not defined.\n", token->str);
        break;
      }
      data_t data = referenced_symbol->data;
      if(is_assignment == 3){
        data = symbol->data;
        switch (*(((token_t*)(token - 1))->str)) {
          case '+': data += referenced_symbol->data; break;
          case '-': data -= referenced_symbol->data; break;
          case '*': data *= referenced_symbol->data; break;
          case '/': data /= referenced_symbol->data; break;
          case '^': data = pow(data, referenced_symbol->data); break;
        }
      }else if(is_assignment == 4){
        data = function(referenced_symbol->data);
      }
      is_assignment = 2;
      symbol = set_symbol(symbol_token->str, data);
      if(!symbol){
        printf("Error allocating new symbol\n");
        return -1;
      }
    }
    else if(is_assignment == 2 && token->type == OPERATOR){
      is_assignment = 3;
    }else if(token->type == END){
      if(symbol){
        print_symbol(symbol);
      }else if(symbol_token){
        printf("Variable \"%s\" not defined.\n", symbol_token->str);
      }
      break;
    }else{
      printf("Unexpected token: ");
      token->print(token);
      printf("\n");
      printf("DEBUG INFO: ");
      print_tokens(tokens);
      break;
    }
  }while(token->type != END && (token = token + 1));
  return 0;
}
//----------------------------------------------------------------------
void free_tokens(token_t* tokens)
{
  size_t i = 0;
  do {
    free((tokens + i)->str);
  } while ((tokens + i++)->type != END);
  free(tokens);
}
//----------------------------------------------------------------------
void free_symbols(void)
{
  for (size_t i = 0; i < symbol_count; i++) {
    symbol_t* symbol = symbols + i;
    symbol->print = debug;
    free(symbol->str);
  }
  free(symbols);
  symbol_count = 0;
  symbols = 0;
}
//------------------------------------------------------------------------------
int main(int argc, char** argv){
  char*  prompt     = "\\>";
  char*  line       = NULL;
  size_t line_len   = 0;
  printf("Type \".help\" for help.\n");
  printf("%s",prompt);
  int err = 0;
  while(getline(&line, &line_len, stdin) != -1){
    //tokenize
    token_t* tokens = NULL;
    if (tokenize(&tokens, line, line_len) < 0){
      printf("Error during tokenization\n");
      err = 1;
    }
    if(tokens != NULL){
      //print_tokens(tokens);
      if(!err && parser1(tokens) < 0){
        printf("Error during parsing 1\n");
        err = 1;
      }
      if(!err && parser2(tokens) < 0){
        printf("Error during parsing 2\n");
        err = 1;
      }
      //print_tokens(tokens);
    }
    if(tokens){
      free_tokens(tokens);
    }
    if(err){
      break;
    }
    printf("%s",prompt);
  }
  free(line);
  free_symbols();
  return 0;
}
