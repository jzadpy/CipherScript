#!/usr/bin/env python3
"""
CipherScript - A cryptography-focused scripting language
Transpiles .cycl files to Python - Inspired by PyML's clean architecture
Maintains original CipherScript syntax without YAML formatting
"""

import re
import os
import sys
import tempfile
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Token types
class TokenType(Enum):
    COMMAND = "COMMAND"
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    NUMBER = "NUMBER"
    KEYWORD = "KEYWORD"
    TO = "TO"
    WITH = "WITH"
    AND = "AND"
    FILE = "FILE"
    NEWLINE = "NEWLINE"
    EOF = "EOF"

@dataclass
class Token:
    type: TokenType
    value: str
    line: int = 0
    column: int = 0

class CipherScriptLexer:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.column = 1
        
        # Keywords and commands - expanded for more algorithms
        self.keywords = {
            'generate', 'set', 'encrypt', 'decrypt', 'display', 'save', 'load',
            'verify', 'sign', 'renew', 'to', 'with', 'and', 'file', 'result',
            'aes', 'chacha20', 'rsa', 'ecdsa', 'sha256', 'sha512', 'sha1', 'md5', 
            'hmac', 'mac', 'signature', 'message', 'cbc', 'gcm', 'ctr'
        }
        
    def current_char(self) -> Optional[str]:
        if self.pos >= len(self.text):
            return None
        return self.text[self.pos]
    
    def advance(self):
        if self.pos < len(self.text) and self.text[self.pos] == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        self.pos += 1
    
    def skip_whitespace(self):
        while self.current_char() and self.current_char().isspace() and self.current_char() != '\n':
            self.advance()
    
    def skip_comment(self):
        # Skip # comments
        while self.current_char() and self.current_char() != '\n':
            self.advance()
    
    def read_string(self) -> str:
        quote_char = self.current_char()
        self.advance()  # skip opening quote
        
        value = ""
        while self.current_char() and self.current_char() != quote_char:
            if self.current_char() == '\\':
                self.advance()
                if self.current_char() == 'n':
                    value += '\n'
                elif self.current_char() == 't':
                    value += '\t'
                elif self.current_char() == '\\':
                    value += '\\'
                elif self.current_char() == quote_char:
                    value += quote_char
                else:
                    value += self.current_char()
            else:
                value += self.current_char()
            self.advance()
        
        if self.current_char() == quote_char:
            self.advance()  # skip closing quote
        
        return value
    
    def read_identifier(self) -> str:
        value = ""
        while (self.current_char() and 
               (self.current_char().isalnum() or self.current_char() in '_.')):
            value += self.current_char()
            self.advance()
        return value
    
    def read_number(self) -> str:
        value = ""
        while self.current_char() and (self.current_char().isdigit() or self.current_char() in '._b'):
            value += self.current_char()
            self.advance()
        return value
    
    def tokenize(self) -> List[Token]:
        tokens = []
        
        while self.current_char():
            if self.current_char().isspace():
                if self.current_char() == '\n':
                    tokens.append(Token(TokenType.NEWLINE, '\n', self.line, self.column))
                    self.advance()
                else:
                    self.skip_whitespace()
                continue
            
            if self.current_char() == '#':
                self.skip_comment()
                continue
            
            if self.current_char() in '"\'':
                string_val = self.read_string()
                tokens.append(Token(TokenType.STRING, string_val, self.line, self.column))
                continue
            
            if self.current_char().isdigit():
                num_val = self.read_number()
                tokens.append(Token(TokenType.NUMBER, num_val, self.line, self.column))
                continue
            
            if self.current_char().isalpha() or self.current_char() == '_':
                identifier = self.read_identifier()
                
                if identifier.lower() == 'to':
                    tokens.append(Token(TokenType.TO, identifier, self.line, self.column))
                elif identifier.lower() == 'with':
                    tokens.append(Token(TokenType.WITH, identifier, self.line, self.column))
                elif identifier.lower() == 'and':
                    tokens.append(Token(TokenType.AND, identifier, self.line, self.column))
                elif identifier.lower() == 'file':
                    tokens.append(Token(TokenType.FILE, identifier, self.line, self.column))
                elif identifier.lower() in self.keywords:
                    tokens.append(Token(TokenType.KEYWORD, identifier, self.line, self.column))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, identifier, self.line, self.column))
                continue
            
            # Skip unknown characters
            self.advance()
        
        tokens.append(Token(TokenType.EOF, '', self.line, self.column))
        return tokens

# AST Node classes
@dataclass
class ASTNode:
    pass

@dataclass
class GenerateCommand(ASTNode):
    var_name: str
    key_size: str
    algorithm: str

@dataclass
class SetCommand(ASTNode):
    var_name: str
    value: Any

@dataclass
class EncryptCommand(ASTNode):
    key_size: str
    message: str
    key_var: str

@dataclass
class DecryptCommand(ASTNode):
    ciphertext_var: str
    key_var: str
    key_size: str
    algorithm: str

@dataclass
class DisplayCommand(ASTNode):
    var_name: str

@dataclass
class SaveCommand(ASTNode):
    var_name: str
    filename: str

@dataclass
class LoadCommand(ASTNode):
    var_name: str
    filename: str

@dataclass
class HashCommand(ASTNode):
    var_name: str
    algorithm: str
    message: str

class CipherScriptParser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def current_token(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]  # EOF token
        return self.tokens[self.pos]
    
    def advance(self):
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
    
    def expect_token(self, expected_types: list) -> Token:
        token = self.current_token()
        if token.type not in expected_types:
            types_str = " or ".join([t.name for t in expected_types])
            raise SyntaxError(f"Expected {types_str}, got {token.type.name} '{token.value}' at line {token.line}")
        self.advance()
        return token
    
    def parse(self) -> List[ASTNode]:
        commands = []
        
        while self.current_token().type != TokenType.EOF:
            if self.current_token().type == TokenType.NEWLINE:
                self.advance()
                continue
                
            command = self.parse_command()
            if command:
                commands.append(command)
        
        return commands
    
    def parse_command(self) -> Optional[ASTNode]:
        token = self.current_token()
        
        if token.type != TokenType.KEYWORD:
            raise SyntaxError(f"Expected command at line {token.line}")
        
        command = token.value.lower()
        self.advance()
        
        if command == 'generate':
            return self.parse_generate()
        elif command == 'set':
            return self.parse_set()
        elif command == 'encrypt':
            return self.parse_encrypt()
        elif command == 'decrypt':
            return self.parse_decrypt()
        elif command == 'display':
            return self.parse_display()
        elif command == 'save':
            return self.parse_save()
        elif command == 'load':
            return self.parse_load()
        else:
            raise SyntaxError(f"Unknown command: {command}")
    
    def parse_generate(self) -> GenerateCommand:
        # generate rkey 256b aes
        var_name = self.expect_token([TokenType.KEYWORD, TokenType.IDENTIFIER]).value
        key_size = self.expect_token([TokenType.NUMBER, TokenType.IDENTIFIER]).value
        algorithm = self.expect_token([TokenType.KEYWORD, TokenType.IDENTIFIER]).value
        return GenerateCommand(var_name, key_size, algorithm)
    
    def parse_set(self) -> SetCommand:
        # set key to rkey OR set hash to sha256 "Message"
        var_name = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        
        if self.current_token().type == TokenType.TO:
            self.advance()
            value_token = self.current_token()
            
            if value_token.value.lower() == "result":
                self.advance()
                return SetCommand(var_name, "result")
            elif value_token.value.lower() in ["sha256", "sha512", "md5"]:
                algorithm = value_token.value
                self.advance()
                message = self.expect_token([TokenType.STRING]).value
                return HashCommand(var_name, algorithm, message)
            else:
                value = value_token.value
                self.advance()
                return SetCommand(var_name, value)
        
        raise SyntaxError(f"Invalid set command syntax at line {self.current_token().line}")
    
    def parse_encrypt(self) -> EncryptCommand:
        # encrypt 256b "Message" with key
        key_size = self.expect_token([TokenType.NUMBER, TokenType.IDENTIFIER]).value
        message = self.expect_token([TokenType.STRING]).value
        self.expect_token([TokenType.WITH])
        key_var = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        return EncryptCommand(key_size, message, key_var)
    
    def parse_decrypt(self) -> DecryptCommand:
        # decrypt citext with key 256b aes
        ciphertext_var = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        self.expect_token([TokenType.WITH])
        key_var = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        key_size = self.expect_token([TokenType.NUMBER, TokenType.IDENTIFIER]).value
        algorithm = self.expect_token([TokenType.KEYWORD, TokenType.IDENTIFIER]).value
        return DecryptCommand(ciphertext_var, key_var, key_size, algorithm)
    
    def parse_display(self) -> DisplayCommand:
        # display ptext
        var_name = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        return DisplayCommand(var_name)
    
    def parse_save(self) -> SaveCommand:
        # save key file "key.key"
        var_name = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        self.expect_token([TokenType.FILE])
        filename = self.expect_token([TokenType.STRING]).value
        return SaveCommand(var_name, filename)
    
    def parse_load(self) -> LoadCommand:
        # load key file "key.key"
        var_name = self.expect_token([TokenType.IDENTIFIER, TokenType.KEYWORD]).value
        self.expect_token([TokenType.FILE])
        filename = self.expect_token([TokenType.STRING]).value
        return LoadCommand(var_name, filename)

class CipherScriptTranspiler:
    def __init__(self):
        self.python_code = []
        self.imports = set()
        
    def add_import(self, import_stmt: str):
        self.imports.add(import_stmt)
    
    def transpile(self, commands: List[ASTNode]) -> str:
        # Add necessary imports inspired by PyML's clean structure
        self.add_import("import os")
        self.add_import("import base64")
        self.add_import("import hashlib")
        self.add_import("import hmac")
        self.add_import("from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes")
        self.add_import("from cryptography.hazmat.backends import default_backend")
        
        # Initialize variables - clean like PyML
        self.python_code = [
            "# Generated Python code from CipherScript",
            "# Transpiled from .cycl to .py",
            "",
            "variables = {}",
            "last_result = None",
            ""
        ]
        
        # Process each command
        for command in commands:
            self.transpile_command(command)
        
        # Build final code like PyML does
        imports_code = "\n".join(sorted(self.imports))
        main_code = "\n".join(self.python_code)
        
        return f"{imports_code}\n\n{main_code}"
    
    def transpile_command(self, command: ASTNode):
        if isinstance(command, GenerateCommand):
            self.transpile_generate(command)
        elif isinstance(command, SetCommand):
            self.transpile_set(command)
        elif isinstance(command, EncryptCommand):
            self.transpile_encrypt(command)
        elif isinstance(command, DecryptCommand):
            self.transpile_decrypt(command)
        elif isinstance(command, DisplayCommand):
            self.transpile_display(command)
        elif isinstance(command, SaveCommand):
            self.transpile_save(command)
        elif isinstance(command, LoadCommand):
            self.transpile_load(command)
        elif isinstance(command, HashCommand):
            self.transpile_hash(command)
    
    def transpile_generate(self, command: GenerateCommand):
        algorithm = command.algorithm.lower()
        
        if algorithm == 'aes':
            self.python_code.extend([
                f"# Generate {command.key_size} AES key",
                f"key_size_str = {repr(command.key_size)}.lower()",
                "if key_size_str.endswith('b'):",
                "    key_size_bits = int(key_size_str[:-1])",
                "    key_size_bytes = key_size_bits // 8",
                "else:",
                "    key_size_bytes = int(key_size_str) // 8",
                "",
                f"variables[{repr(command.var_name)}] = os.urandom(key_size_bytes)",
                f"print('Generated ' + str(key_size_bits) + '-bit AES key in ' + {repr(command.var_name)})",
                ""
            ])
        elif algorithm == 'chacha20':
            self.python_code.extend([
                f"# Generate ChaCha20 key (always 256-bit)",
                f"variables[{repr(command.var_name)}] = os.urandom(32)",
                f"print('Generated 256-bit ChaCha20 key in ' + {repr(command.var_name)})",
                ""
            ])
        elif algorithm == 'rsa':
            self.add_import("from cryptography.hazmat.primitives.asymmetric import rsa")
            self.python_code.extend([
                f"# Generate RSA key pair",
                f"key_size_str = {repr(command.key_size)}.lower()",
                "if key_size_str.endswith('b'):",
                "    key_size_bits = int(key_size_str[:-1])",
                "else:",
                "    key_size_bits = int(key_size_str)",
                "",
                "private_key = rsa.generate_private_key(",
                "    public_exponent=65537,",
                "    key_size=key_size_bits,",
                "    backend=default_backend()",
                ")",
                f"variables[{repr(command.var_name)}] = private_key",
                f"variables[{repr(command.var_name + '_public')}] = private_key.public_key()",
                f"print('Generated ' + str(key_size_bits) + '-bit RSA key pair in ' + {repr(command.var_name)})",
                ""
            ])
        else:
            self.python_code.extend([
                f"raise ValueError('Unsupported algorithm: {command.algorithm}')",
                ""
            ])
    
    def transpile_set(self, command: SetCommand):
        if command.value == "result":
            self.python_code.extend([
                f"variables[{repr(command.var_name)}] = last_result",
                f"print('Set ' + {repr(command.var_name)} + ' = ' + type(last_result).__name__)",
                ""
            ])
        else:
            self.python_code.extend([
                f"if {repr(command.value)} in variables:",
                f"    variables[{repr(command.var_name)}] = variables[{repr(command.value)}]",
                f"    print('Set ' + {repr(command.var_name)} + ' = ' + type(variables[{repr(command.value)}]).__name__)",
                f"else:",
                f"    variables[{repr(command.var_name)}] = {repr(command.value)}",
                f"    print('Set ' + {repr(command.var_name)} + ' = string')",
                ""
            ])
    
    def transpile_encrypt(self, command: EncryptCommand):
        # Detect algorithm from context - default to AES if not specified
        algorithm = 'aes'  # default
        mode = 'cbc'       # default
        
        self.python_code.extend([
            f"# Encrypt message",
            f"print('Encrypting message...')",
            f"if {repr(command.key_var)} not in variables:",
            f"    raise ValueError('Key variable ' + {repr(command.key_var)} + ' not found')",
            "",
            f"key = variables[{repr(command.key_var)}]",
            f"message = {repr(command.message)}.encode('utf-8')",
            f"print('Original message: ' + {repr(command.message)})",
            "",
            "# Parse key size",
            f"key_size_str = {repr(command.key_size)}.lower()",
            "if key_size_str.endswith('b'):",
            "    key_size_bits = int(key_size_str[:-1])",
            "else:",
            "    key_size_bits = int(key_size_str)",
            "",
            "# Determine algorithm based on key type and size",
            "if isinstance(key, bytes):",
            "    if len(key) == 32:",
            "        # Could be AES-256 or ChaCha20",
            "        algorithm = 'aes'",
            "    elif len(key) == 24:",
            "        algorithm = 'aes'  # AES-192",
            "    elif len(key) == 16:",
            "        algorithm = 'aes'  # AES-128",
            "    ",
            "    if algorithm == 'aes':",
            "        # AES-CBC encryption",
            "        iv = os.urandom(16)",
            "        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())",
            "        encryptor = cipher.encryptor()",
            "        ",
            "        # Apply PKCS7 padding",
            "        block_size = 16",
            "        pad_length = block_size - (len(message) % block_size)",
            "        padded_message = message + bytes([pad_length] * pad_length)",
            "        ",
            "        ciphertext = encryptor.update(padded_message) + encryptor.finalize()",
            "        result = iv + ciphertext",
            "        last_result = base64.b64encode(result).decode('utf-8')",
            "        print('Successfully encrypted with ' + str(key_size_bits) + '-bit AES-CBC')",
            "else:",
            "    raise ValueError('Unsupported key type for encryption')",
            ""
        ])
    
    def transpile_decrypt(self, command: DecryptCommand):
        algorithm = command.algorithm.lower()
        
        self.python_code.extend([
            f"# Decrypt ciphertext",
            f"print('Decrypting ciphertext...')",
            f"if {repr(command.ciphertext_var)} not in variables:",
            f"    raise ValueError('Ciphertext variable ' + {repr(command.ciphertext_var)} + ' not found')",
            f"if {repr(command.key_var)} not in variables:",
            f"    raise ValueError('Key variable ' + {repr(command.key_var)} + ' not found')",
            "",
            f"ciphertext_b64 = variables[{repr(command.ciphertext_var)}]",
            f"key = variables[{repr(command.key_var)}]",
            "",
            "# Parse key size",
            f"key_size_str = {repr(command.key_size)}.lower()",
            "if key_size_str.endswith('b'):",
            "    key_size_bits = int(key_size_str[:-1])",
            "else:",
            "    key_size_bits = int(key_size_str)",
            "",
        ])
        
        if algorithm == 'aes':
            self.python_code.extend([
                "# AES decryption",
                "data = base64.b64decode(ciphertext_b64)",
                "iv = data[:16]",
                "ciphertext_data = data[16:]",
                "",
                "cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())",
                "decryptor = cipher.decryptor()",
                "padded_plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()",
                "",
                "# Remove PKCS7 padding",
                "if len(padded_plaintext) > 0:",
                "    pad_length = padded_plaintext[-1]",
                "    if pad_length <= 16 and pad_length > 0:",
                "        # Verify padding is correct",
                "        padding_bytes = padded_plaintext[-pad_length:]",
                "        if all(b == pad_length for b in padding_bytes):",
                "            plaintext = padded_plaintext[:-pad_length]",
                "        else:",
                "            plaintext = padded_plaintext",
                "    else:",
                "        plaintext = padded_plaintext",
                "else:",
                "    plaintext = padded_plaintext",
                "",
                "try:",
                "    last_result = plaintext.decode('utf-8')",
                "except UnicodeDecodeError:",
                "    last_result = plaintext.decode('utf-8', errors='replace')",
                "variables['ptext'] = last_result",
                "print('Successfully decrypted with ' + str(key_size_bits) + '-bit AES-CBC')",
                ""
            ])
        else:
            self.python_code.extend([
                f"raise ValueError('Unsupported decryption algorithm: {algorithm}')",
                ""
            ])
    
    def transpile_display(self, command: DisplayCommand):
        self.python_code.extend([
            f"# Display variable",
            f"if {repr(command.var_name)} in variables:",
            f"    value = variables[{repr(command.var_name)}]",
            "    if isinstance(value, bytes):",
            f"        print({repr(command.var_name)} + ': ' + base64.b64encode(value).decode('utf-8'))",
            "    else:",
            f"        print({repr(command.var_name)} + ': ' + str(value))",
            "else:",
            f"    print('Variable ' + {repr(command.var_name)} + ' not found')",
            ""
        ])
    
    def transpile_save(self, command: SaveCommand):
        self.python_code.extend([
            f"# Save variable to file",
            f"if {repr(command.var_name)} not in variables:",
            f"    raise ValueError('Variable ' + {repr(command.var_name)} + ' not found')",
            "",
            f"value = variables[{repr(command.var_name)}]",
            f"with open({repr(command.filename)}, 'wb') as f:",
            "    if isinstance(value, bytes):",
            "        f.write(value)",
            "    elif isinstance(value, str):",
            "        f.write(value.encode('utf-8'))",
            f"print('Saved ' + {repr(command.var_name)} + ' to ' + {repr(command.filename)})",
            ""
        ])
    
    def transpile_load(self, command: LoadCommand):
        self.python_code.extend([
            f"# Load file into variable",
            "try:",
            f"    with open({repr(command.filename)}, 'rb') as f:",
            f"        variables[{repr(command.var_name)}] = f.read()",
            f"    print('Loaded ' + {repr(command.filename)} + ' into ' + {repr(command.var_name)})",
            "except FileNotFoundError:",
            f"    print('File ' + {repr(command.filename)} + ' not found')",
            ""
        ])
    
    def transpile_hash(self, command: HashCommand):
        self.python_code.extend([
            f"# Calculate {command.algorithm.upper()} hash",
            f"print('Calculating {command.algorithm.upper()} hash...')",
            f"message = {repr(command.message)}.encode('utf-8')",
            f"hash_obj = hashlib.{command.algorithm.lower()}(message)",
            f"variables[{repr(command.var_name)}] = hash_obj.hexdigest()",
            f"print('Successfully calculated {command.algorithm.upper()} hash')",
            ""
        ])

class CipherScript:
    """Main CipherScript class - inspired by PyML's clean architecture"""
    
    def __init__(self):
        self.transpiler = CipherScriptTranspiler()
    
    def compile_file(self, filename: str, output_file: str = None) -> str:
        """Compile .cycl file to Python - like PyML does"""
        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        code = None
        
        for encoding in encodings:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    code = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if code is None:
            raise Exception(f"Could not read file '{filename}' with any supported encoding")
        
        # Clean up any problematic characters
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        
        python_code = self.compile(code)
        
        if output_file is None:
            output_file = filename.replace('.cycl', '.py')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(python_code)
        
        print(f"Compiled '{filename}' -> '{output_file}'")
        return output_file
    
    def compile(self, code: str) -> str:
        """Compile CipherScript code to Python"""
        try:
            # Tokenize
            lexer = CipherScriptLexer(code)
            tokens = lexer.tokenize()
            
            # Parse
            parser = CipherScriptParser(tokens)
            commands = parser.parse()
            
            # Transpile
            python_code = self.transpiler.transpile(commands)
            return python_code
            
        except Exception as e:
            raise Exception(f"CipherScript Compilation Error: {e}")
    
    def run_file(self, filename: str):
        """Compile and run .cycl file - PyML inspired with temporary file cleanup"""
        import tempfile
        
        # Create temporary Python file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as temp_file:
            python_code = self.compile_file_to_string(filename)
            temp_file.write(python_code)
            temp_python_file = temp_file.name
        
        print(f"Running {filename}")
        print("=" * 50)
        
        try:
            # Execute the generated Python code
            with open(temp_python_file, 'r', encoding='utf-8') as f:
                exec(f.read())
            print("=" * 50)
            print("Execution completed successfully!")
        except Exception as e:
            print("=" * 50)
            print(f"Error during execution: {e}")
        finally:
            # Always clean up the temporary file
            try:
                os.unlink(temp_python_file)
            except:
                pass  # Ignore errors when deleting temp file
    
    def compile_file_to_string(self, filename: str) -> str:
        """Compile .cycl file to Python string without saving to disk"""
        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        code = None
        
        for encoding in encodings:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    code = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if code is None:
            raise Exception(f"Could not read file '{filename}' with any supported encoding")
        
        # Clean up any problematic characters
        code = code.replace('\r\n', '\n').replace('\r', '\n')
        
        return self.compile(code)

def create_examples():
    """Create example files like PyML does"""
    os.makedirs('examples', exist_ok=True)
    
    basic_example = '''# CipherScript Basic Example
# AES encryption with different key sizes

generate rkey 256b aes
set key to rkey
encrypt 256b "Hello CipherScript!" with key
set citext to result
decrypt citext with key 256b aes
display ptext
set hash to sha256 "Hello CipherScript!"
display hash
'''
    
    advanced_example = '''# CipherScript Advanced Example
# Multiple encryption algorithms

# AES with different key sizes
generate aes128_key 128b aes
generate aes256_key 256b aes

# ChaCha20 key
generate chacha_key 256b chacha20

# RSA key pair
generate rsa_key 2048b rsa

# Test AES-128
encrypt 128b "Secret message with AES-128" with aes128_key
set encrypted_aes128 to result

# Test AES-256
encrypt 256b "Secret message with AES-256" with aes256_key
set encrypted_aes256 to result

# Decrypt both
decrypt encrypted_aes128 with aes128_key 128b aes
display ptext

decrypt encrypted_aes256 with aes256_key 256b aes
display ptext

# Hash comparison
set hash1 to sha256 "Secret message with AES-128"
set hash2 to sha512 "Secret message with AES-256"
display hash1
display hash2
'''
    
    algorithms_example = '''# CipherScript - Supported Algorithms Demo

# Symmetric Encryption
generate aes_128 128b aes
generate aes_192 192b aes  
generate aes_256 256b aes
generate chacha_key 256b chacha20

# Asymmetric Encryption
generate rsa_1024 1024b rsa
generate rsa_2048 2048b rsa
generate rsa_4096 4096b rsa

# Display all generated keys
display aes_128
display aes_256
display chacha_key
display rsa_2048
'''
    
    with open('examples/basic.cycl', 'w') as f:
        f.write(basic_example)
    
    with open('examples/advanced.cycl', 'w') as f:
        f.write(advanced_example)
        
    with open('examples/algorithms.cycl', 'w') as f:
        f.write(algorithms_example)
    
    print("Created example files:")
    print("  examples/basic.cycl      - Basic AES encryption")
    print("  examples/advanced.cycl   - Multiple algorithms") 
    print("  examples/algorithms.cycl - All supported algorithms")

def main():
    """Main CLI - inspired by PyML's interface"""
    if len(sys.argv) < 2:
        print("CipherScript - Cryptography scripting language")
        print("\nUsage:")
        print("  python cycl.py <script.cycl>           # Compile and run")
        print("  python cycl.py <script.cycl> -c       # Compile only")
        print("  python cycl.py <script.cycl> -o file  # Compile to specific file")
        print("  python cycl.py --examples             # Create example files")
        return
    
    if sys.argv[1] == '--examples':
        create_examples()
        return
    
    filename = sys.argv[1]
    
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
    
    if not filename.endswith('.cycl'):
        print("Error: CipherScript files must have .cycl extension")
        return
    
    cs = CipherScript()
    
    try:
        if len(sys.argv) > 2:
            if sys.argv[2] == '-c':
                # Compile only
                cs.compile_file(filename)
            elif sys.argv[2] == '-o' and len(sys.argv) > 3:
                # Compile to specific output file
                cs.compile_file(filename, sys.argv[3])
            else:
                print("Unknown option. Use -c for compile only, -o <file> for custom output")
        else:
            # Compile and run
            cs.run_file(filename)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()