# DOMPROS - AI-Powered Penetration Testing Assistant

## Introduction

### What is DeepSeek R1?

DeepSeek-R1 is an AI model developed by Chinese artificial intelligence startup DeepSeek. Released in 20th January 2025, R1 holds its own against (and in some cases surpasses) the reasoning capabilities of some of the world’s most advanced foundation models — but at a fraction of the operating cost, according to the company. R1 is also open sourced under an MIT license, allowing free commercial and academic use.

There are three key ideas behind DeepSeek R1:

- Chain of Thought — Making the model explain itself.
- Reinforcement Learning — Letting it train itself.
- Distillation — Shrinking it without losing power.

### What is DOMPROS?

DOMPROS is an AI-Powered Penetration Testing Assistant that fully generated by DeepSeek R1.  It assists penetration testers to perform penetration tests.  It provides ```Search Exploit```, ```Analyze Findings```, ```Brainstrom``` and ```Tools Suggest``` to the penetration testers during their works.  The project is created and designed by Samiux on Feburary 26, 2025.

You can use any LLM (Large Language Model) in the market while it is running on Ollama.  We recommended using DeepSeek R1 Distilled LLM as it can run on any low-end computer with or without GPUs.  The RAM is required at least 8GB.

## Installation

### 0x01 Docker on Kali Linux v2024.4

```
sudo apt-get update

sudo install -m 0755 -d /etc/apt/keyrings

sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc

sudo chmod a+r /etc/apt/keyrings/docker.asc
```
```
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "bookworm") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

sudo apt-get install docker-ce
```

### 0x02 Docker on Ubuntu 24.04 LTS

```
sudo snap install docker
```

or

```
sudo install -m 0755 -d /etc/apt/keyrings

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

sudo chmod a+r /etc/apt/keyrings/docker.asc
```
```
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update

sudo apt install docker-ce
```

### 0x03 Ollama

The configuration can run on any CPU with 8GB RAM.

```
sudo docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama --restart always ollama/ollama
```

### 0x04 LLM

The configuration can run on any CPU with 8GB RAM.

DeepSeek-R1-Distill-Qwen-7B
```
sudo docker exec -it ollama ollama pull deepseek-r1:7b
```

DeepSeek-R1-Distill-Llama-8B
```
sudo docker exec -it ollama ollama pull deepseek-r1:8b
```

### 0x05 DOMPROS

Set up Python Virtualenv that does not mess up with the original OS.

```
sudo apt install python3-virtualenv

virtualenv -p python3 venv
source venv/bin/activate
```

Install dependencies

```
pip3 install colorama requests duckduckgo_search
```

Install DOMPROS

```
git clone https://github.com/samiux/dompros

cd dompros

chmod +x dompros.py
```

## Run

Run the following command and follows the instruction on the screen.

```
./dompros.py
```

[+] Ollama is ready!

    ▓█████▄  ▒█████   ███▄ ▄███▓ ██▓███   ██▀███   ▒█████   ██████ 
    ▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ 
    ░██   █▌▒██░  ██▒▓██    ▓██░▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   
    ░▓█▄   ▌▒██   ██░▒██    ▒██ ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░  ▒   ██▒
    ░▒████▓ ░ ████▓▒░▒██▒   ░██▒▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░▒██████▒▒
     ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
     ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░
     ░ ░  ░ ░ ░ ░ ▒  ░      ░   ░░         ░░   ░ ░ ░ ░ ▒  ░  ░  ░  
       ░        ░ ░         ░               ░         ░ ░        ░  
    
	AI-Powered Penetration Testing Assistant
	DOMPROS Version 1.0 | Copyright DeepSeek R1
	Dated Feb 26, 2025


Main Menu:
1. Search Exploit Procedure
2. Analyze Findings
3. Brainstorm Problem
4. Suggest Tools
0. Exit

[?] Enter your choice (0-4): 

The ```pentest_assistant.log``` can be found at the current directory.

## Configuration

You can either use ```deepseek-r1:7b (DeepSeek-R1-Distill-Qwen-7B)``` or ```deepseek-r1:8b (DeepSeek-R1-Distill-Llama-8B)``` by modifiy the ```MODEL``` at ```dompros.py```.  Default is using ```deepseek-r1:7b (DeepSeek-R1-Distill-Qwen-7B)```.

## License

DOMPROS is open sourced under an MIT license, allowing free commercial and academic use.

Samiux  
OSCE  OSCP  OSWP  
Feburary 26, 2025, Hong Kong, China  

## Reference

- [DeepSeek](https://www.deepseek.com/)  
- [DeepSeek Github](https://github.com/deepseek-ai)  
- [Ollama](https://ollama.com/)  
- [Ollama Github](https://github.com/ollama/ollama)  

