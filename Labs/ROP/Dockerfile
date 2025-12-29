# Bring down ubuntu image
FROM ubuntu:latest

# Install Socat and GCC
RUN apt-get update && apt-get install build-essential python3 pip python3-venv nano wget -y

# Make Source Directory
RUN mkdir /usr/src/ROP/

#Copy In Source Code
COPY ROP.c /usr/src/ROP/ROP.c

# Move flag in to root of the file system
COPY flag.txt /root/flag.txt

#Compile Source Code
RUN gcc /usr/src/ROP/ROP.c -o /usr/bin/ROP -Wall -Wextra -std=gnu99 -Wno-deprecated-declarations -fno-stack-protector -no-pie -fno-pic

#Change Permissions
RUN chown root:root /usr/bin/ROP
RUN chmod +s /usr/bin/ROP

# Create Default User
RUN useradd -m -s /bin/bash Intern

#Change User
USER Intern

#Change Working Directory
WORKDIR /home/Intern/

#Make directory for venv
RUN mkdir .venv/

#Copy README into Intern home
COPY README.md .

# Run Default Command
CMD ["/bin/bash"]
