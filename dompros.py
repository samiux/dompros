#!/usr/bin/env python

#######################################################
# DOMPROS - AI-Powered Penetrattion Testing Assistant #
# by DeepSeek R1 & Samiux (MIT License)               #
#                                                     #
# Version 0.0.5 Dated Mar 01, 2025                    #
#                                                     #
# Powered by DeepSeek R1 and Ollama                   #
# Website - https://samiux.github.io/dompros          #
#######################################################

import argparse
import logging
import subprocess
import sys
import json
from datetime import datetime
from colorama import Fore, Style, init
import requests
from duckduckgo_search import DDGS
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import ANSI

# Initialize colorama
init(autoreset=True)

# Configuration
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_CHECK = "http://localhost:11434/api/tags"
MODEL_NAME = "deepseek-r1:7b"
LOG_FILE = "pentest_assistant.log"

# Initialize logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    encoding='utf-8'
)

def print_banner():
    """Display creative ASCII banner"""
    banner = f"""
{Fore.MAGENTA}
██████╗  ██████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔══██╗██╔═══██╗██╔════╝
██║  ██║██║   ██║██╔████╔██║██████╔╝██████╔╝██║   ██║███████╗
██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ ██╔══██╗██║   ██║╚════██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     ██║  ██║╚██████╔╝███████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}    DOMPROS - AI-Powered Penetration Testing Assistant
{Fore.WHITE}    Version 0.0.5 | MIT License | Secure your systems!
{Fore.WHITE}    by DeepSeek R1 and Samiux
{Fore.WHITE}    Dated Mar 01, 2025
"""
    print(banner)
    logging.info("Application started with banner display")

def check_ollama():
    """Verify Ollama service availability"""
    try:
        health_check = requests.get(OLLAMA_CHECK, timeout=5)
        if health_check.status_code == 200:
            print(Fore.GREEN + "[+] Ollama service: RUNNING")
            logging.info("Ollama service verified via API")
            return True
                
        print(Fore.RED + "[-] Ollama service not responding!")
        logging.error(f"Ollama API responded with code {health_check.status_code}")
        return False

    except requests.ConnectionError:
        print(Fore.RED + "[-] Ollama service not running! Start with 'ollama serve'")
        logging.error("Ollama service connection failed")
        return False

    except Exception as e:
        logging.error(f"Ollama check failed: {str(e)}")
        print(Fore.RED + f"[-] Ollama check error: {str(e)}")
        return False

def ollama_chat(system_prompt, user_prompt):
    """Communicate with Ollama API with streaming enabled"""
    logging.info(f"Sending request to Ollama\nSystem Prompt: {system_prompt}\nUser Prompt: {user_prompt}")
    try:
        headers = {"Content-Type": "application/json"}
        data = {
            "model": MODEL_NAME,
            "prompt": user_prompt,
            "system": system_prompt,
            "stream": True  # Changed to True
        }
        
        response = requests.post(OLLAMA_ENDPOINT, json=data, headers=headers, timeout=600000, stream=True)
        response.raise_for_status()
        
        full_response = ""
        # Process streaming response
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode('utf-8'))
                if 'response' in chunk:
                    full_response += chunk['response']
                    # Print each chunk as it arrives
                    print(chunk['response'], end='', flush=True)
        
        # Logged during streaming already, not required now.
        #logging.info(f"Received Ollama response: {full_response}")
        return full_response
        
    except Exception as e:
        logging.error(f"Ollama communication failed: {str(e)}")
        return f"Error: {str(e)}"

def search_ddg(query):
    """Search DuckDuckGo with error handling"""
    logging.info(f"Searching DuckDuckGo for: {query}")
    try:
        with DDGS() as ddgs:
            results = [r for r in ddgs.text(query, max_results=10)]
        return "\n".join([f"{i+1}. {r['title']}\n   {r['href']}\n   {r['body']}" for i, r in enumerate(results)])
    except Exception as e:
        logging.error(f"DDG search failed: {str(e)}")
        return f"Search error: {str(e)}"

def get_multiline_input(prompt_text):
    """Collect multi-line input with logging"""
    print(Fore.YELLOW + f"\n{prompt_text} (Enter '.' alone to finish)")
    lines = []
    while True:
        try:
            line = prompt(ANSI(Fore.CYAN + "> " + Style.RESET_ALL))
            logging.info(f"Multi-line input: {line}")
            if line.strip() == '.':
                break
            lines.append(line)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nInput cancelled")
            break
    return '\n'.join(lines)

def handle_command(command, initial_args):
    """Command handler with context-aware processing"""
    system_prompts = {
        "search": (
            "You are a cybersecurity expert. Analyze search results and provide: "
            "1. Vulnerability analysis 2. Exploit procedure 3. Workable payloads "
            "4. Mitigation strategies. Be technical and precise."
        ),
        "analyze": (
            "You are a senior penetration tester. Analyze these findings and provide: "
            "1. Risk assessment 2. Next steps 3. Tool recommendations "
            "4. Exploit code samples. Include both common and novel approaches."
        ),
        "brainstorm": (
            "You are a security researcher. For this problem: "
            "1. Propose 3 unconventional attack vectors 2. Suggest bypass techniques "
            "3. Recommend obscure tools 4. Provide proof-of-concept ideas."
        ),
        "suggest": (
            "You are a cybersecurity tools expert. Recommend: "
            "1. Latest tools 2. Installation commands 3. Usage examples "
            "4. Configuration tips 5. Best practices. Include CLI snippets."
        )
    }

    # Collect multi-line input if needed
    args = initial_args
    if not args and command in ["analyze", "brainstorm", "suggest"]:
        arg_prompt = {
            "analyze": "Paste security findings/scans/vulnerabilities:",
            "brainstorm": "Describe the problem/challenge:",
            "suggest": "Enter tool requirements/use case:",
        }.get(command)
        args = get_multiline_input(arg_prompt)

    logging.info(f"Processing command: {command} with args: {args[:1000]}...")

    if command == "search":
        print(Fore.GREEN + "\n[AI Assistant]\n\n" + Style.RESET_ALL + "<Processing ...>")
        search_results = search_ddg(args)
        user_prompt = f"Search Query: {args}\nResults:\n{search_results}\nProvide detailed analysis:"
        return ollama_chat(system_prompts["search"], user_prompt)
    
    elif command == "analyze":
        print(Fore.GREEN + "\n[AI Assistant]\n\n" + Style.RESET_ALL + "<Processing ...>")
        user_prompt = f"Security Findings:\n{args}\nProvide expert analysis:"
        return ollama_chat(system_prompts["analyze"], user_prompt)
    
    elif command == "brainstorm":
        print(Fore.GREEN + "\n[AI Assistant]\n\n" + Style.RESET_ALL + "<Processing ...>")
        user_prompt = f"Problem Statement:\n{args}\nGenerate creative solutions:"
        return ollama_chat(system_prompts["brainstorm"], user_prompt)
    
    elif command == "suggest":
        print(Fore.GREEN + "\n[AI Assistant]\n\n" + Style.RESET_ALL + "<Processing ...>")
        search_results = search_ddg(f"latest {args} cybersecurity tools 2024 and 2025")
        user_prompt = f"Tool Requirements: {args}\nSearch Results:\n{search_results}\nRecommend tools:"
        return ollama_chat(system_prompts["suggest"], user_prompt)
    
def main():
    if not check_ollama():
        sys.exit(1)

    print(Fore.GREEN + f"[+] {MODEL_NAME}: LOADING")
    
    print_banner()
    print(Fore.CYAN + "Available commands:\n" + 
          Fore.YELLOW + "  search <query>" + Fore.WHITE + "     - Search for vulnerabilities\n" +
          Fore.YELLOW + "  analyze" + Fore.WHITE + "            - Analyze security findings\n" +
          Fore.YELLOW + "  brainstorm" + Fore.WHITE + "         - Generate attack ideas\n" +
          Fore.YELLOW + "  suggest <category>" + Fore.WHITE + " - Get tool recommendations\n" +
          Fore.YELLOW + "  help" + Fore.WHITE + "               - Get help\n" +
          Fore.YELLOW + "  exit" + Fore.WHITE + "               - Quit the program\n")

    while True:
        try:
            user_input = prompt(ANSI(Fore.CYAN + "\npentest> " + Style.RESET_ALL), 
                              multiline=False).strip()
            if not user_input:
                continue
                
            logging.info(f"User command: {user_input}")

            if user_input.lower() == "help":
                print(Fore.CYAN + "\nValid commands: search, analyze, brainstorm, suggest, help, exit")
                logging.info("User get help menu")
                continue
            
            if user_input.lower() == "exit":
                print(Fore.YELLOW + "\n[+] Exiting. Happy hacking!")
                logging.info("User exited the program")
                break
                
            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            
            if command not in ["search", "analyze", "brainstorm", "suggest", "help"]:
                print(Fore.RED + "[-] Invalid command. Valid commands: search, analyze, brainstorm, suggest, help, exit")
                continue
                
            response = handle_command(command, args)
            print(Fore.GREEN + "\n[AI Assistant]\n" + Style.RESET_ALL + response)
            logging.info(f"AI Response: {response[:40000]}...")  # Log partial response
            
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Use 'exit' to quit properly")
        except Exception as e:
            logging.error(f"Critical error: {str(e)}")
            print(Fore.RED + f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
