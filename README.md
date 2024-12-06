# Peer to Peer Distributed File Sharing System

[Screencast from 2024-10-20 16-06-20.webm](https://github.com/user-attachments/assets/ce7825d4-4715-47f2-8117-da04e6ff9ccf)

This assignment is a simple peer-to-peer (P2P) distributed file-sharing system. It involves a tracker and multiple clients that can share files with one another. The clients communicate with the tracker to register and find other peers, and they directly connect to each other to upload and download files.

- In Client Compile using
```bash 
g++ -pthread -o client client.cpp -lcrypto
```

- Client Execution
```bash
./client IP:PORT tracker_info.txt
```
Eg- ./client 127.0.0.1:6000 tracker_info.txt


- In Tracker Compile using
```bash  
g++ tracker.cpp -o tracker -lpthread
```

- Tracker Execution
```bash  
./tracker tracker_info.txt 1
```

## Menu Based Commands

### Client Terminal -

-Sign Up:
```bash
create_user
<<user_id>>
<password>
```

- Login:
```bash
login
<user_id>
<password>
```

- Create Group:
```bash 
create_group <group_id>
```

- Join Group: 
```bash
join_group <group_id>
```

- Leave Group: 
```bash
leave_group <group_id>
```

- Upload File: 
```bash
upload_file 
<file_path>
```

- Download File: 
```bash
download_file 
<file_name> 
```

- Logout: 
```bash
logout
```
- Exit:
```bash
exit
```
