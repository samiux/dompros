#!/usr/bin/env python

import requests
import logging
from colorama import Fore, Style, init
from duckduckgo_search import DDGS
import time
import subprocess

# Initialize Model
MODEL="deepseek-r1:7b"		# DeepSeek-R1-Distill-Qwen-7B
#MODEL="deepseek-r1:14b"	# DeepSeek-R1-Distill-Qwen-14B
#MODEL="deepseek-r1:8b"		# DeepSeek-R1-Distill-Llama-8B

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename='pentest_assistant.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_activity(activity_type, details):
    """Log user and system activities with enhanced details"""
    logging.info(f"{activity_type.upper()} - {details}")

def check_ollama():
    """Check if Ollama is running and ready"""
    try:
        response = requests.get('http://localhost:11434')
        if response.status_code == 200:
            print(Fore.GREEN + "[+] Ollama is ready!")
            log_activity("system", "Ollama is running and ready.")
            return True
    except requests.ConnectionError:
        print(Fore.RED + "[!] Ollama not running! Please start Ollama first.")
        log_activity("system", "Ollama is not running. Connection error.")
        return False

def ollama_post(system_prompt, user_prompt, model=MODEL):
    """Send prompt to Ollama and return response"""
    try:
        log_activity("system", f"Sending request to Ollama with model: {model}")
        log_activity("user", f"System Prompt: {system_prompt}")
        log_activity("user", f"User Prompt: {user_prompt}")
        
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                "model": model,
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": False,
		"temperature": 0.7
            }
        )
        if response.status_code == 404:
            print(Fore.RED + "[!] " + MODEL + " not found, try to pull it first!")
            log_activity("system", MODEL + " not found.  Respone error.")
            quit()
		
        log_activity("system", f"Ollama response received: {response.status_code}")
        return response.json()['response']
    except Exception as e:
        log_activity("error", f"Ollama error: {str(e)}")
        return None

def search_exploit_procedure():
    """Search DuckDuckGo and get exploit procedure"""
    query = input(Fore.CYAN + "[?] Enter your search query: ").strip()
    if not query:
       print(Fore.YELLOW + "[!] Returning to main menu ...")
       return
    print(Fore.GREEN + f"[+] Searching for: {query}")
    log_activity("user", f"Search query: {query}")
    
    with DDGS() as ddgs:
        results = [r for r in ddgs.text(query, max_results=10)]
        log_activity("system", f"DuckDuckGo search results: {results}")
    
    system_prompt = """You are an AI penetration testing expert. Analyze these search results and provide:
    1. Potential vulnerabilities
    2. Proof-of-Concept (PoC) sources and links
    3. Step-by-step exploitation procedure
    4. Example and actual payloads and/or scripts
    5. Recommended mitigation strategies
    6. List of all websites with URLs that you have been read and/or referred"""
    
    response = ollama_post(
        system_prompt,
        f"Search results: {str(results)}\n\nProvide exploitation procedure:"
    )
    
    print(Fore.YELLOW + "\n[AI Recommendation]")
    print(Fore.WHITE + response)
    log_activity("system", f"Exploit procedure generated: {response}")

def analyze_findings():
    """Analyze findings and provide suggestions"""
    findings = input(Fore.CYAN + "[?] Paste your findings here: ").strip()
    if not findings:
        print(Fore.YELLOW + "[!] Returning to main menu ...")
        return
    print(Fore.GREEN + f"[+] Analyzing: {findings}")
    log_activity("user", f"Findings submitted: {findings}")
    
    system_prompt = """You are a senior security analyst. Review these findings and:
    1. Identify critical vulnerabilities
    2. Suggest verification methods
    3. Provide exploitation steps with exact payloads
    4. Recommend tools for further testing"""
    
    response = ollama_post(
        system_prompt,
        f"Findings: {findings}\n\nProvide analysis:"
    )
    
    print(Fore.YELLOW + "\n[AI Analysis]")
    print(Fore.WHITE + response)
    log_activity("system", f"Analysis completed: {response}")

def brainstorm_problem():
    """Brainstorm solutions for complex problems"""
    problem = input(Fore.CYAN + "[?] Describe the problem you're facing: ").strip()
    if not problem:
        print(Fore.YELLOW + "[!] Returning to main menu ...")
        return
    print(Fore.GREEN + F"[+] Brainstorming: {problem}")
    log_activity("user", f"Problem description: {problem}")
    
    system_prompt = """You are a creative cybersecurity expert. For the given problem:
    1. Suggest multiple attack vectors
    2. Propose unconventional testing methods
    3. Identify potential misconfigurations
    4. Recommend bypass techniques"""
    
    response = ollama_post(
        system_prompt,
        f"Problem: {problem}\n\nProvide brainstorming solutions:"
    )
    
    print(Fore.YELLOW + "\n[AI Brainstorming]")
    print(Fore.WHITE + response)
    log_activity("system", f"Brainstorming solutions: {response}")

def suggest_tools():
    """Recommend tools with usage instructions"""
    task = input(Fore.CYAN + "[?] What task do you need to perform? ").strip()
    if not task:
        print(Fore.YELLOW + "[!] Returning to main menu ...")
        return
    print(Fore.GREEN + f"[+] Recommending: {task}")
    log_activity("user", f"Task for tool suggestion: {task}")
    
    system_prompt = """You are a penetration testing tools expert. For the given task:
    1. Recommend appropriate tools
    2. Provide installation commands
    3. Give usage examples with command-line options
    4. Include tips for effective usage
    5. Cover reconnaissance, exploitation and post-exploitation"""
    
    response = ollama_post(
        system_prompt,
        f"Task: {task}\n\nRecommend tools:"
    )
    
    print(Fore.YELLOW + "\n[AI Tool Recommendations]")
    print(Fore.WHITE + response)
    log_activity("system", f"Tool recommendations: {response}")

def print_banner():
    """Display colorful banner"""
    print(Fore.MAGENTA + """
    ▓█████▄  ▒█████   ███▄ ▄███▓ ██▓███   ██▀███   ▒█████   ██████ 
    ▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ 
    ░██   █▌▒██░  ██▒▓██    ▓██░▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   
    ░▓█▄   ▌▒██   ██░▒██    ▒██ ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░  ▒   ██▒
    ░▒████▓ ░ ████▓▒░▒██▒   ░██▒▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░▒██████▒▒
     ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
     ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░
     ░ ░  ░ ░ ░ ░ ▒  ░      ░   ░░         ░░   ░ ░ ░ ░ ▒  ░  ░  ░  
       ░        ░ ░         ░               ░         ░ ░        ░  
    """)
    print(Fore.CYAN +  "	AI-Powered Penetration Testing Assistant")
    print(Fore.GREEN + "	DOMPROS Version 1.0.1 | Copyright DeepSeek R1 & Samiux")
    print(Fore.GREEN + "	Dated Feb 28, 2025\n")
    log_activity("system", "Pentest Assistant started.")

def main():
    if not check_ollama():
        return
    
    print_banner()
    
    while True:
        print(Fore.CYAN + "\nMain Menu:")
        print(Fore.GREEN + "1. Search Exploit Procedure")
        print(Fore.GREEN + "2. Analyze Findings")
        print(Fore.GREEN + "3. Brainstorm Problem")
        print(Fore.GREEN + "4. Suggest Tools")
        print(Fore.RED + "0. Exit")
        
        choice = input(Fore.YELLOW + "\n[?] Enter your choice (0-4): ").strip()
        log_activity("user", f"Menu choice selected: {choice}")
        
        if choice == '1':
            search_exploit_procedure()
        elif choice == '2':
            analyze_findings()
        elif choice == '3':
            brainstorm_problem()
        elif choice == '4':
            suggest_tools()
        elif choice == '0':
            print(Fore.GREEN + "\n[+] Exiting... Happy hacking!")
            log_activity("system", "Pentest Assistant exited.")
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")
            log_activity("error", "Invalid menu choice selected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        quit()
