# Binary Exploitation: ROP Lab

## Purpose

The goal of this lab is to give students an introduction into binary exploitation. While this is not the most basic form of exploitation, it is a form that can give some good insight into how a computer works, how a processor runs through code, and how different code security features work.

## Background

**What is binary exploitation?** Binary exploitation is the practice of taking advantage of a flaw in a compiled piece of software, in order to gain access, or further your access within a system. Common exploits within this category include things like buffer overflow, use after free, or return oriented programming. Each technique requires different conditions, so not all these attacks are possible in every situation, however, we will cover some ways of finding the bread crumbs that will lead us to know which attack to use.

**What attack will we use in this lab?** In this lab we will leverage return oriented programming (ROP). We will get into specifics on why we are doing this later, but due to the specifics of our binary, this will be our approach for the lab.

**What is ROP?** ROP or return oriented programming is an exploitation technique used against binaries that looks to take control of the program's control flow and execute machine code on its behalf. This is a technique that can be used in the presence of something like [executable-space protection](https://en.wikipedia.org/wiki/Executable-space_protection), which is something that would stop us from using a buffer overflow to execute shell code. We gather assembly instructions from the binary which are called gadgets, we hope to gather enough gadgets to eventually run commands from either the code itself, or shared libraries which are linked with the binary. The end goal being, running commands on the system we are attacking.

**What does this lab entail?** This lab will be a local privilege escalation lab targeting an Ubuntu 24.04 instance that is running in a Docker container. Using ROP we will exploit a binary that has been configured with SetUID and SetGID permissions in linux. These permissions make the binary run as root in this case as that is the own of the file, giving us a golden opportunity for privilege escalation. The code is also vulnerable to a buffer overflow. These few attributes cause the perfect storm for us to be able to exploit this system, hopefully gaining root access to the system. After we get root access to the system, we can find the flag that is contained within the system.

**Lab Setup:**
- Victim
    - OS: Ubuntu 24.04 Docker Container
    - Vulnerable Application: ROP
    - Target: Flag.txt

## Lab Guide

### Scope



### Getting Started

Before we begin our lab, let's ensure we have everything that we need to be successful. If you haven't already visited [Docker Setup](https://weber-cyber-club.github.io/extradocs/docker/docker-setup/), to get Docker installed and set up for labs. If you are confident in your Docker skills, don't even worry, just keep going through the lab.

Now with Docker installed, let's begin checking and installing the dependencies that we will need for this demonstration. For this lab we are going to need Pyhton 3 and PWNTools, both of which should already be installed on your system.

To check if Python 3 exists just run:

  python3 --version

As long as a version appears, you have Python 3 on your system already! If, for some reason, you did not have Python 3 installed, just run:

  # Ensures your repository indexes are current
   sudo apt update

  # Installs Python 3

  sudo apt install python3




## Questions

## Conclusion

## Python VENV

```

python3 -m venv build/

source build/bin/activate

deactivate

```