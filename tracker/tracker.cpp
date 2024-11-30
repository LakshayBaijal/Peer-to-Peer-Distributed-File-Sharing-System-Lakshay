#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <map>
#include <vector>

using namespace std;
#define BACKLOG 10

struct FileMetadata {
    string file_name;
    off_t file_size;
    string file_hash;
    size_t num_chunks;
    vector<string> chunk_hashes;
    vector<pair<string, int>> seeders;
};

map<string, string> users; 
map<string, vector<string>> groups; 
map<string, FileMetadata> files;

void loadUserDetails();
void saveUserDetails();
void* clientHandler(void* socket_desc);

pthread_mutex_t user_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t group_lock = PTHREAD_MUTEX_INITIALIZER; 
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER; 

int main(int argc, char* argv[]) 
{
    srand(time(0)); 
    if (argc != 3) 
    {
        cerr << "Format ./tracker tracker_info.txt tracker_no" << endl;
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) 
    {
        cerr << "Failed to open tracker info file." << endl;
        return 1;
    }

    char buffer[256];
    ssize_t bytes_read;
    string data;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) 
    {
        buffer[bytes_read] = '\0';
        data += buffer;
    }
    close(fd);

    istringstream iss(data);
    vector<pair<string, int>> tracker_list;
    string ip;
    int port;
    while (iss >> ip >> port) 
    {
        tracker_list.emplace_back(ip, port);
    }

    if (tracker_list.empty()) 
    {
        cerr << "No tracker information found." << endl;
        return 1;
    }

    int tracker_no = stoi(argv[2]);
    if (tracker_no < 0 || tracker_no >= tracker_list.size()) 
    {
        cerr << "Invalid tracker number." << endl;
        return 1;
    }

    ip = tracker_list[tracker_no].first;
    port = tracker_list[tracker_no].second;

    loadUserDetails();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) 
    {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    cout << "Tracker bound to IP: " << ip << " Port: " << port << endl;

    if (listen(server_fd, BACKLOG) < 0) 
    {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    cout << "Tracker is listening on " << ip << ":" << port << endl;

    while ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen))) 
    {
        cout << "Accepted connection from " << inet_ntoa(address.sin_addr) << ":" << ntohs(address.sin_port) << endl;
        pthread_t thread_id;
        int* new_sock = new int;
        *new_sock = new_socket;

        if (pthread_create(&thread_id, NULL, clientHandler, (void*)new_sock) < 0) 
        {
            perror("Could not create thread");
            delete new_sock;
        } 
        else 
        {
            cout << "Created thread to handle client." << endl;
        }

        pthread_detach(thread_id);
    }

    if (new_socket < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    close(server_fd);
    return 0;
}

void loadUserDetails() {
    int fd = open("user_details.txt", O_RDONLY);
    if (fd >= 0) 
    {
        char buffer[256];
        ssize_t bytes_read;
        string data;

        while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) 
        {
            buffer[bytes_read] = '\0';
            data += buffer;
            size_t pos;
            while ((pos = data.find('\n')) != string::npos) 
            {
                string line = data.substr(0, pos);
                data.erase(0, pos + 1);
                size_t space_pos = line.find(' ');
                if (space_pos != string::npos) 
                {
                    string username = line.substr(0, space_pos);
                    string password = line.substr(space_pos + 1);
                    users[username] = password;
                }
            }
        }
        close(fd);
        cout << "User details loaded successfully." << endl;
    } 
    else 
    {
        cout << "No user details found, starting fresh." << endl;
    }
}

void saveUserDetails() {
    int fd = open("user_details.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) 
    {
        for (const auto& user : users) {
            string line = user.first + " " + user.second + "\n";
            write(fd, line.c_str(), line.size());
        }
        close(fd);
        cout << "User details saved successfully." << endl;
    } 
    else 
    {
        perror("Failed to open user_details.txt for writing");
    }
}

void* clientHandler(void* socket_desc) 
{
    int sock = *(int*)socket_desc;
    delete (int*)socket_desc;

    char buffer[4096];

    bool logged_in = false;
    bool group_operation_done = false;
    string username;

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(sock, (struct sockaddr *)&addr, &addr_size);
    string client_ip = inet_ntoa(addr.sin_addr);

    while (true) 
    { 
        memset(buffer, 0, sizeof(buffer));

        int read_size = read(sock, buffer, sizeof(buffer));
        if (read_size <= 0) 
        {
            cout << "Client disconnected." << endl;
            break;
        }

        string command(buffer, read_size);
        cout << "Received command: " << command << endl;

        command.erase(command.find_last_not_of(" \n\r") + 1);

        if (!logged_in) 
        {
            if (command.rfind("register", 0) == 0) 
            { 
                size_t space_pos = command.find(' ');
                size_t second_space_pos = command.find(' ', space_pos + 1);
                if (space_pos != string::npos && second_space_pos != string::npos) 
                {
                    username = command.substr(space_pos + 1, second_space_pos - space_pos - 1);
                    string password = command.substr(second_space_pos + 1);

                    pthread_mutex_lock(&user_lock);
                    if (users.find(username) == users.end()) 
                    {
                        users[username] = password;
                        saveUserDetails(); 
                        pthread_mutex_unlock(&user_lock);
                        const char* response = "Registration successful";
                        write(sock, response, strlen(response));
                        cout << "User registered: " << username << endl;
                    } 
                    else 
                    {
                        pthread_mutex_unlock(&user_lock);
                        const char* response = "Username already exists";
                        write(sock, response, strlen(response));
                        cout << "Registration failed: Username already exists." << endl;
                    }
                } 
                else
                {
                    const char* response = "Invalid registration format";
                    write(sock, response, strlen(response));
                    cout << "Invalid registration format received." << endl;
                }
            } else if (command.rfind("login", 0) == 0) 
            {
                size_t space_pos = command.find(' ');
                size_t second_space_pos = command.find(' ', space_pos + 1);
                if (space_pos != string::npos && second_space_pos != string::npos) 
                {
                    username = command.substr(space_pos + 1, second_space_pos - space_pos - 1);
                    string password = command.substr(second_space_pos + 1);

                    pthread_mutex_lock(&user_lock); 
                    if (users.find(username) != users.end() && users[username] == password) {
                        pthread_mutex_unlock(&user_lock);
                        const char* response = "Login successful";
                        write(sock, response, strlen(response));
                        cout << "User logged in: " << username << endl;
                        logged_in = true;
                    } 
                    else 
                    {
                        pthread_mutex_unlock(&user_lock);
                        const char* response = "Invalid credentials";
                        write(sock, response, strlen(response));
                        cout << "Login failed for user: " << username << endl;
                    }
                } 
                else 
                {
                    const char* response = "Invalid login format";
                    write(sock, response, strlen(response));
                    cout << "Invalid login format received." << endl;
                }
            } 
            else 
            {
                const char* response = "Unknown command";
                write(sock, response, strlen(response));
                cout << "Unknown command received: " << command << endl;
            }
        } 
        else 
        {
            if (command == "logout") 
            {
                logged_in = false;
                group_operation_done = false;
                const char* response = "Logout successful";
                write(sock, response, strlen(response));
                cout << "User logged out: " << username << endl;
            } 
            else if (!group_operation_done && command.rfind("create_group", 0) == 0) 
            { 
                size_t space_pos = command.find(' ');
                if (space_pos != string::npos) {
                    string group_name = command.substr(space_pos + 1);

                    pthread_mutex_lock(&group_lock); 
                    if (groups.find(group_name) == groups.end()) 
                    {
                        groups[group_name].push_back(username);
                        pthread_mutex_unlock(&group_lock);
                        const char* response = "Group created successfully";
                        write(sock, response, strlen(response));
                        cout << "Group created: " << group_name << " by user: " << username << endl;
                        group_operation_done = true;
                    } 
                    else 
                    {
                        pthread_mutex_unlock(&group_lock);
                        const char* response = "Group already exists";
                        write(sock, response, strlen(response));
                        cout << "Group creation failed: Group already exists." << endl;
                    }
                } 
                else 
                {
                    const char* response = "Invalid group creation format";
                    write(sock, response, strlen(response));
                    cout << "Invalid group creation format received." << endl;
                }
            } 
            else if (!group_operation_done && command.rfind("join_group", 0) == 0) 
            { 
                size_t space_pos = command.find(' ');
                if (space_pos != string::npos) {
                    string group_name = command.substr(space_pos + 1);

                    pthread_mutex_lock(&group_lock);
                    if (groups.find(group_name) != groups.end()) 
                    {
                        bool is_member = false;
                        for (const auto& member : groups[group_name]) 
                        {

                            if (member == username) 
                            {
                                is_member = true;
                                break;
                            }
                        }
                        if (!is_member) 
                        {
                            groups[group_name].push_back(username);
                            pthread_mutex_unlock(&group_lock);
                            const char* response = "Joined group successfully";
                            write(sock, response, strlen(response));
                            cout << "User " << username << " joined group: " << group_name << endl;
                            group_operation_done = true;
                        } 
                        else 
                        {
                            pthread_mutex_unlock(&group_lock);
                            const char* response = "Already a member of the group";
                            write(sock, response, strlen(response));
                            cout << "Join group failed: User already a member." << endl;
                        }
                    } else 
                    {
                        pthread_mutex_unlock(&group_lock);
                        const char* response = "Group does not exist";
                        write(sock, response, strlen(response));
                        cout << "Join group failed: Group does not exist." << endl;
                    }
                } 
                else 
                {
                    const char* response = "Invalid group join format";
                    write(sock, response, strlen(response));
                    cout << "Invalid group join format received." << endl;
                }
            } 
            
            else if (command.rfind("upload_file_metadata", 0) == 0) {
                // format: upload_file_metadata <file_name> <file_size> <client_port> <file_hash> <num_chunks> <chunk_hashes>
                istringstream iss(command);
                string cmd, file_name, file_hash;
                off_t file_size;
                int client_port;
                size_t num_chunks;
                iss >> cmd >> file_name >> file_size >> client_port >> file_hash >> num_chunks;

                vector<string> chunk_hashes(num_chunks);
                for (size_t i = 0; i < num_chunks; ++i) 
                {
                    iss >> chunk_hashes[i];
                }


                pthread_mutex_lock(&file_lock);
                if (files.find(file_name) == files.end()) 
                {
                    FileMetadata file_meta;
                    file_meta.file_name = file_name;
                    file_meta.file_size = file_size;
                    file_meta.file_hash = file_hash;
                    file_meta.num_chunks = num_chunks;
                    file_meta.chunk_hashes = chunk_hashes;
                    file_meta.seeders.push_back({client_ip, client_port});
                    files[file_name] = file_meta;
                }
                else 
                {
                    files[file_name].seeders.push_back({client_ip, client_port});
                }
                pthread_mutex_unlock(&file_lock);

                const char* response = "File metadata received";
                write(sock, response, strlen(response));
                cout << "Received file metadata for " << file_name << " from " << username << endl;
            } 
            
            
            
            else if (command.rfind("download_file", 0) == 0) 
            {

                size_t space_pos = command.find(' ');
                if (space_pos != string::npos) {
                    string file_name = command.substr(space_pos + 1);

                    pthread_mutex_lock(&file_lock);
                    if (files.find(file_name) != files.end()) 
                    {
                        // <file_size> <file_hash> <num_chunks> <chunk_hashes> <num_seeders> <seeder_ip> <seeder_port>
                        ostringstream oss;
                        FileMetadata& file_meta = files[file_name];
                        oss << file_meta.file_size << " " << file_meta.file_hash << " " << file_meta.num_chunks;
                        for (const auto& hash : file_meta.chunk_hashes) 
                        {
                            oss << " " << hash;
                        }
                        oss << " " << file_meta.seeders.size();
                        for (const auto& seeder : file_meta.seeders) 
                        {
                            oss << " " << seeder.first << " " << seeder.second;
                        }
                        string response = oss.str();
                        write(sock, response.c_str(), response.size());
                        pthread_mutex_unlock(&file_lock);
                        cout << "Provided file metadata for " << file_name << " to " << username << endl;
                    } 
                    else 
                    {
                        pthread_mutex_unlock(&file_lock);
                        const char* response = "File not found";
                        write(sock, response, strlen(response));
                        cout << "File " << file_name << " not found." << endl;
                    }
                } 
                else 
                {
                    const char* response = "Invalid download_file command format";
                    write(sock, response, strlen(response));
                    cout << "Invalid download_file format received." << endl;
                }
            } else {
                const char* response = "Invalid command. Please try again.";
                write(sock, response, strlen(response));
                cout << "Invalid command received: " << command << endl;



                if (!group_operation_done) {
                    continue;
                }
            }
        }
    }

    if (logged_in) {
        cout << "User logged out: " << username << endl;
    }

    cout << "Client disconnected." << endl;
    close(sock);
    pthread_exit(NULL);
}
